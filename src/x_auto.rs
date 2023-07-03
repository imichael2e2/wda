use crate::error::Result;

pub trait BasicAutomation {
    fn go_url(&self, url: &str) -> Result<()>;

    fn get_url(&self) -> Result<String>;

    fn page_src(&self, save_to: Option<&str>) -> Result<Option<Vec<u8>>>;

    fn print_page(&self, save_to: &str) -> Result<()>;

    fn sshot_page(&self, save_to: &str) -> Result<()>;

    fn sshot_elem(&self, elem_id: &str, save_to: &str) -> Result<()>;

    fn find_elem_by_css(&self, selector: &str) -> Result<String>;

    fn find_elems_by_css(&self, selector: &str) -> Result<Vec<String>>;

    fn eval(&self, script: &str, args: Vec<&str>) -> Result<String>;

    fn eval_async(&self, script: &str, args: Vec<&str>) -> Result<String>;
}

#[cfg(feature = "extra_auto")]
pub trait ExtraAutomation {
    fn sshot_page_allv(&self, url: &str, save_to: &str) -> Result<()>;

    fn sshot_curr_allv(&self, save_to: &str) -> Result<()>;
}
