pub(crate) mod mux;
pub(crate) mod virtio_serial;

pub(crate) use virtio_serial::{VirtioSerialControlEndpoint, VirtioSerialControlError};
