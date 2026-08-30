//! Reusable slots addressed by plain indexes.

use core::fmt;
#[cfg(not(feature = "alloc"))]
use core::mem::MaybeUninit;

use super::Full;

/// Reusable slots addressed by plain indexes: a growable list of `Option<T>`.
///
/// `N` is ignored here: with `alloc` the slab grows instead of running out.
pub(crate) struct Slab<T, const N: usize> {
    #[cfg(feature = "alloc")]
    items: alloc::vec::Vec<Option<T>>,

    #[cfg(not(feature = "alloc"))]
    used: [bool; N],
    #[cfg(not(feature = "alloc"))]
    items: [MaybeUninit<T>; N],
}

/// One shared panic site for every empty-slot access, so each `get`/`get_mut`/
/// `remove` call site is a test and a branch rather than its own panic.
#[cold]
#[inline(never)]
fn no_item() -> ! {
    panic!("no item at this index")
}

#[cfg(feature = "alloc")]
impl<T, const N: usize> Slab<T, N> {
    pub const fn new() -> Self {
        Self {
            items: alloc::vec::Vec::new(),
        }
    }

    /// Add an item, returning its index. Free slots are reused.
    ///
    /// The item is built by calling `f` with the index it is going to get, so that
    /// items can store their own handle. `f` is not called if there is no room.
    pub fn add_with(&mut self, f: impl FnOnce(usize) -> T) -> Result<usize, Full> {
        let index = match self.items.iter().position(Option::is_none) {
            Some(index) => index,
            None => {
                // Grow by an empty slot, then fill it in place below: building the
                // item into a temporary and pushing that would copy the whole
                // thing, and the items here are large.
                self.items.push(None);
                self.items.len() - 1
            }
        };
        self.items[index] = Some(f(index));
        Ok(index)
    }

    /// Whether `add_with` would fail. Never true with `alloc`.
    pub fn is_full(&self) -> bool {
        false
    }

    /// Remove the item at `index`, dropping it.
    ///
    /// It is dropped where it lies rather than moved out first, which matters
    /// because the items here (sockets, interfaces) are large.
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    pub fn remove(&mut self, index: usize) {
        match self.items.get_mut(index) {
            Some(slot) if slot.is_some() => *slot = None,
            _ => no_item(),
        }
    }

    /// Take the item at `index` out of the slab.
    ///
    /// Only the tests want the item back; everything else drops it in place with
    /// [`remove`](Self::remove).
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    #[cfg(test)]
    pub fn take(&mut self, index: usize) -> T {
        match self.items.get_mut(index).and_then(Option::take) {
            Some(item) => item,
            None => no_item(),
        }
    }

    /// Get a reference to the item at `index`.
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    pub fn get(&self, index: usize) -> &T {
        match self.items.get(index) {
            Some(Some(item)) => item,
            _ => no_item(),
        }
    }

    /// Get a mutable reference to the item at `index`.
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    pub fn get_mut(&mut self, index: usize) -> &mut T {
        match self.items.get_mut(index) {
            Some(Some(item)) => item,
            _ => no_item(),
        }
    }

    /// Index of the first occupied slot at or after `from`, if any.
    pub fn next_occupied(&self, from: usize) -> Option<usize> {
        (from..self.items.len()).find(|&index| self.items[index].is_some())
    }

    /// Iterate over all occupied slots, with their indexes.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &T)> {
        self.items
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| Some((index, slot.as_ref()?)))
    }

    /// Iterate over all occupied slots, with their indexes.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &mut T)> {
        self.items
            .iter_mut()
            .enumerate()
            .filter_map(|(index, slot)| Some((index, slot.as_mut()?)))
    }
}

#[cfg(not(feature = "alloc"))]
#[allow(unsafe_code)]
// `filter_map` with a `bool::then` inside codegens smaller than clippy's
// preferred `filter` then `map`, in `iter`/`iter_mut` below.
#[allow(clippy::filter_map_bool_then)]
impl<T, const N: usize> Slab<T, N> {
    pub const fn new() -> Self {
        Self {
            used: [false; N],
            items: [const { MaybeUninit::uninit() }; N],
        }
    }

    /// Add an item, returning its index. Free slots are reused.
    ///
    /// The item is built by calling `f` with the index it is going to get, so that
    /// items can store their own handle. `f` is not called if there is no room.
    pub fn add_with(&mut self, f: impl FnOnce(usize) -> T) -> Result<usize, Full> {
        let index = self.used.iter().position(|&used| !used).ok_or(Full)?;
        // The item is built straight into its slot: through a temporary it would
        // be copied, and the items here are large.
        self.items[index].write(f(index));
        self.used[index] = true;
        Ok(index)
    }

    /// Whether `add_with` would fail.
    pub fn is_full(&self) -> bool {
        self.used.iter().all(|&used| used)
    }

    /// Remove the item at `index`, dropping it.
    ///
    /// It is dropped where it lies rather than moved out first, which matters
    /// because the items here (sockets, interfaces) are large.
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    pub fn remove(&mut self, index: usize) {
        if !matches!(self.used.get(index), Some(true)) {
            no_item();
        }
        self.used[index] = false;
        // SAFETY: the slot was occupied, so its item is initialized. Its flag is
        // already clear, so nothing reads the item again.
        unsafe { self.items[index].assume_init_drop() };
    }

    /// Take the item at `index` out of the slab.
    ///
    /// Only the tests want the item back; everything else drops it in place with
    /// [`remove`](Self::remove).
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    #[cfg(test)]
    pub fn take(&mut self, index: usize) -> T {
        if !matches!(self.used.get(index), Some(true)) {
            no_item();
        }
        self.used[index] = false;
        // SAFETY: the slot was occupied, so its item is initialized. Its flag is
        // already clear, so nothing reads the item again.
        unsafe { self.items[index].assume_init_read() }
    }

    /// Get a reference to the item at `index`.
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    pub fn get(&self, index: usize) -> &T {
        if !matches!(self.used.get(index), Some(true)) {
            no_item();
        }
        // SAFETY: an occupied slot holds an initialized item.
        unsafe { self.items[index].assume_init_ref() }
    }

    /// Get a mutable reference to the item at `index`.
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    pub fn get_mut(&mut self, index: usize) -> &mut T {
        if !matches!(self.used.get(index), Some(true)) {
            no_item();
        }
        // SAFETY: an occupied slot holds an initialized item, and `&mut self` makes
        // this the only reference to it.
        unsafe { self.items[index].assume_init_mut() }
    }

    /// Index of the first occupied slot at or after `from`, if any.
    pub fn next_occupied(&self, from: usize) -> Option<usize> {
        (from..N).find(|&index| self.used[index])
    }

    /// Iterate over all occupied slots, with their indexes.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &T)> {
        self.used
            .iter()
            .zip(self.items.iter())
            .enumerate()
            // SAFETY: an occupied slot holds an initialized item.
            // `filter` then `map` would be the clippy-preferred shape, but it
            // codegens worse here.
            .filter_map(|(index, (&used, slot))| used.then(|| (index, unsafe { slot.assume_init_ref() })))
    }

    /// Iterate over all occupied slots, with their indexes.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &mut T)> {
        self.used
            .iter()
            .zip(self.items.iter_mut())
            .enumerate()
            // SAFETY: an occupied slot holds an initialized item, and the slice
            // iterator hands out each slot exactly once, so the references it
            // yields never alias.
            .filter_map(|(index, (&used, slot))| used.then(|| (index, unsafe { slot.assume_init_mut() })))
    }
}

#[cfg(not(feature = "alloc"))]
#[allow(unsafe_code)]
impl<T, const N: usize> Drop for Slab<T, N> {
    fn drop(&mut self) {
        for index in 0..N {
            if self.used[index] {
                // SAFETY: an occupied slot holds an initialized item, and the whole
                // thing is going away.
                unsafe { self.items[index].assume_init_drop() };
            }
        }
    }
}

impl<T, const N: usize> Default for Slab<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for Slab<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_slab_add_remove_reuse() {
        let mut slab: Slab<usize, 8> = Slab::new();
        assert_eq!(slab.add_with(|i| i * 10), Ok(0));
        assert_eq!(slab.add_with(|i| i * 10), Ok(1));
        assert_eq!(slab.add_with(|i| i * 10), Ok(2));

        slab.remove(1);

        // The freed slot is reused.
        assert_eq!(slab.add_with(|i| i * 10), Ok(1));
        assert_eq!(slab.add_with(|i| i * 10), Ok(3));

        let items: std::vec::Vec<_> = slab.iter_mut().map(|(i, item)| (i, *item)).collect();
        assert_eq!(items, vec![(0, 0), (1, 10), (2, 20), (3, 30)]);
    }

    #[test]
    #[should_panic]
    fn test_slab_remove_empty_slot() {
        let mut slab: Slab<u32, 8> = Slab::new();
        slab.add_with(|_| 1u32).unwrap();
        slab.remove(0);
        slab.remove(0);
    }

    #[test]
    #[should_panic]
    fn test_slab_get_empty_slot() {
        let slab: Slab<u32, 8> = Slab::new();
        slab.get(0);
    }

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn test_slab_full() {
        let mut slab: Slab<usize, 2> = Slab::new();
        assert_eq!(slab.add_with(|i| i), Ok(0));
        assert!(!slab.is_full());
        assert_eq!(slab.add_with(|i| i), Ok(1));
        assert!(slab.is_full());
        assert_eq!(slab.add_with(|i| i), Err(Full));
        slab.remove(0);
        assert!(!slab.is_full());
        assert_eq!(slab.add_with(|i| i), Ok(0));
    }

    /// Removed items are dropped, and so are the ones left in the slab.
    #[test]
    fn test_slab_drops_items() {
        use std::rc::Rc;

        let counter = Rc::new(());
        {
            let mut slab: Slab<Rc<()>, 4> = Slab::new();
            for _ in 0..3 {
                slab.add_with(|_| counter.clone()).unwrap();
            }
            assert_eq!(Rc::strong_count(&counter), 4);
            slab.remove(1);
            assert_eq!(Rc::strong_count(&counter), 3);
        }
        assert_eq!(Rc::strong_count(&counter), 1);
    }
}
