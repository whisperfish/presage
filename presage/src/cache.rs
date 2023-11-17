use std::cell::Cell;

pub(crate) struct CacheCell<T: Clone> {
    cell: Cell<Option<T>>,
}

impl<T: Clone> Clone for CacheCell<T> {
    fn clone(&self) -> Self {
        let value = self.cell.replace(None);
        self.cell.set(value.clone());
        Self {
            cell: Cell::new(value),
        }
    }
}

impl<T: Clone> Default for CacheCell<T> {
    fn default() -> Self {
        Self {
            cell: Cell::new(None),
        }
    }
}

impl<T: Clone> CacheCell<T> {
    pub fn get(&self, factory: impl FnOnce() -> T) -> T {
        let value = match self.cell.replace(None) {
            Some(value) => value,
            None => factory(),
        };
        self.cell.set(Some(value.clone()));
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_cell() {
        let cache: CacheCell<String> = Default::default();

        let value = cache.get(|| ("Hello, World!".to_string()));
        assert_eq!(value, "Hello, World!");
        let value = cache.get(|| panic!("I should not run"));
        assert_eq!(value, "Hello, World!");
    }
}
