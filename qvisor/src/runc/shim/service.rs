// Copyright (c) 2021 Quark Container Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

use containerd_shim::api::*;
use containerd_shim::protos::protobuf::{Message, SingularPtrField};
use containerd_shim::monitor::{monitor_subscribe, Subject, Subscription, Topic};
use containerd_shim::protos::ttrpc::context::Context;
use containerd_shim::publisher::RemotePublisher;
use containerd_shim::spawn;
use containerd_shim::util::*;
use containerd_shim::Config;
use containerd_shim::ExitSignal;
use containerd_shim::Result;
use containerd_shim::Shim;
use containerd_shim::StartOpts;

//use super::super::super::qlib::common;
//use super::super::super::qlib::common::*;

use super::shim_task::*;

//pub type ShimResult<T> = std::result::Result<T, containerd_shim::Error>;

const GROUP_LABELS: [&str; 2] = [
    "io.containerd.runc.v2.group",
    "io.kubernetes.cri.sandbox-id",
];
// Implementation for shim service, see https://github.com/containerd/containerd/blob/main/runtime/v2/README.md
pub struct Service {
    exit: Arc<ExitSignal>,
    id: String,
    namespace: String,
}

impl Shim for Service {
    type T = ShimTask;

    fn new(_runtime_id: &str, id: &str, namespace: &str, _config: &mut Config) -> Self {
        let exit = Arc::new(ExitSignal::default());
        Service {
            exit: exit.clone(),
            id: id.to_string(),
            namespace: namespace.to_string(),
        }
    }

    fn start_shim(&mut self, opts: StartOpts) -> Result<String> {
        info!("Shim Service start_shim start");
        let mut grouping = opts.id.clone();
        let spec = read_spec_from_file("")?;
        debug!("spec is {:?}", &spec);
        match spec.annotations() {
            Some(annotations) => {
                for label in GROUP_LABELS.iter() {
                    if let Some(value) = annotations.get(*label) {
                        grouping = value.to_string();
                        break;
                    }
                }
            }
            None => {}
        }

        let (_, address) = spawn(opts, &grouping, Vec::new())?;
        write_address(&address)?;
        info!("Shim Service start_shim end");
        Ok(address.to_string())
    }

    fn delete_shim(&mut self) -> Result<DeleteResponse> {
        info!("Shim Service delete_shim start");
        // TODO: revisit this, this should try to read container from pwd and delete
        //self.task.Destroy()?;

        let mut resp = DeleteResponse::new();
        // sigkill
        resp.exit_status = 137;
        resp.exited_at = SingularPtrField::some(timestamp()?);
        info!("Shim Service delete_shim finish");
        Ok(resp)
    }

    fn wait(&mut self) {
        info!("Shim Service wait start");
        self.exit.wait();
        info!("Shim Service wait finish");
    }

    fn create_task_service(&self, publisher: RemotePublisher) -> Self::T {
        let (tx, rx) = channel();
        let task = ShimTask::New(self.namespace.as_str(), self.exit.clone(), tx);

        forward(publisher, self.namespace.clone(), rx);

        let s = monitor_subscribe(Topic::All).expect("monitor subscribe failed");
        self.process_exits(s, &task);
        task
    }
}

fn forward(publisher: RemotePublisher, ns: String, rx: Receiver<(String, Box<dyn Message>)>) {
    std::thread::spawn(move || {
        for (topic, e) in rx.iter() {
            publisher
                .publish(Context::default(), &topic, &ns, e)
                .unwrap_or_else(|e| warn!("publish {} to containerd: {}", topic, e));
        }
    });
}

impl Service {
    pub fn process_exits(&self, s: Subscription, _task: &ShimTask) {
        debug!("process_exits start ...");
        std::thread::spawn(move || {
            for e in s.rx.iter() {
                if let Subject::Pid(_pid) = e.subject {
                    debug!("quark sandbox process_exits receive exit event: {}, quark shim exiting ...", &e);
                    unsafe {
                        // ucallServer::HandleSignal SIGKILL all processes
                        libc::kill(0, 9);
                    }
                }
            }
        });
    }
}
