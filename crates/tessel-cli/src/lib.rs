//! Tessel: core library of the `tessel` CLI.
//!
//! Modules: inventory (`inventory`), Unity detection (`unity`), TSP models (`model`),
//! export policy (`policy`), secret scanning (`secrets`), package creation
//! (`package`), verification (`verify`), comparison (`diff`), reporting (`report`) and static analysis of binaries and Unity builds (`analyze`, `binary`, `unity_build`).
//!
//! Design guarantee: no function in this crate spawns processes or executes
//! content from the inspected project.

pub mod analyze;
pub mod binary;
pub mod diff;
pub mod inventory;
pub mod model;
pub mod package;
pub mod policy;
pub mod report;
pub mod secrets;
pub mod unity;
pub mod unity_build;
pub mod util;
pub mod verify;
