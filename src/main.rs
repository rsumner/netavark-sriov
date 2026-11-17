mod alloc;
mod cmd;
mod driver;
mod error;
mod names;
mod nft;
mod options;
mod redirect;
mod reserved;
mod setup;
mod state;
mod sysfs;

#[cfg(test)]
mod test_util;

use std::path::Path;

use netavark::network::types::{Network, NetworkPluginExec, StatusBlock};
use netavark::plugin::{Info, Plugin, PluginExec, API_VERSION};

struct Sriov;

impl Plugin for Sriov {
    fn create(&self, network: Network) -> Result<Network, Box<dyn std::error::Error>> {
        Ok(setup::create_network(&setup::Layout::system(), network)?)
    }

    fn setup(
        &self,
        netns: String,
        opts: NetworkPluginExec,
    ) -> Result<StatusBlock, Box<dyn std::error::Error>> {
        Ok(setup::setup_network(
            &setup::Layout::system(),
            Path::new(&netns),
            &opts,
        )?)
    }

    fn teardown(
        &self,
        netns: String,
        opts: NetworkPluginExec,
    ) -> Result<(), Box<dyn std::error::Error>> {
        setup::teardown_network(&setup::Layout::system(), Path::new(&netns), &opts)?;
        Ok(())
    }
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("netavark_sriov=info"),
    )
    .target(env_logger::Target::Stderr)
    .format_timestamp_secs()
    .init();

    let info = Info::new(
        env!("CARGO_PKG_VERSION").to_owned(),
        API_VERSION.to_owned(),
        None,
    );
    PluginExec::new(Sriov, info).exec();
}
