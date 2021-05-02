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
    pub fn get<E>(&self, factory: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        let value = match self.cell.replace(None) {
            Some(value) => value,
            None => factory()?,
        };
        self.cell.set(Some(value.clone()));
        Ok(value)
    }

    pub fn clear(&self) {
        self.cell.set(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;

    #[test]
    fn test_cache_cell() {
        let cache: CacheCell<String> = Default::default();

        let value = cache
            .get(|| Ok::<_, Infallible>("Hello, World!".to_string()))
            .unwrap();
        assert_eq!(value, "Hello, World!");
        let value = cache
            .get(|| -> Result<String, Infallible> { panic!("I should not run") })
            .unwrap();
        assert_eq!(value, "Hello, World!");

        let new_cache = cache.clone(); // clone should not touch the cache
        let value = cache
            .get(|| -> Result<String, Infallible> { panic!("I should not run") })
            .unwrap();
        assert_eq!(value, "Hello, World!");

        cache.clear();
        let value = cache
            .get(|| Ok::<_, Infallible>("Hi, Amigo!".to_string()))
            .unwrap();
        assert_eq!(value, "Hi, Amigo!");
        let value = new_cache
            .get(|| -> Result<String, Infallible> { panic!("I should not run") })
            .unwrap();
        assert_eq!(value, "Hello, World!");
    }
}
