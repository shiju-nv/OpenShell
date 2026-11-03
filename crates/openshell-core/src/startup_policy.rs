// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup policy signals exchanged between the supervisor and gateway.

use serde::{Deserialize, Serialize};
use tonic::{Status, metadata::MetadataMap};

const ATTACH_POLICY_REFUSAL_HEADER: &str = "openshell-attach-policy-refusal";

/// Response metadata set by a gateway that created a sandbox policy revision.
pub const POLICY_REVISION_CREATED_HEADER: &str = "openshell-policy-revision-created";

/// A backend policy refusal that the gateway can describe without backend text.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachPolicyRefusal {
    /// The requested workload identity conflicts with the boundary's identity.
    WorkloadIdentityMismatch,
    /// The requested policy differs from the backend's admitted profile.
    PolicyProfileMismatch,
}

impl AttachPolicyRefusal {
    /// Public diagnostic for this reason.
    pub fn message(self) -> &'static str {
        match self {
            Self::WorkloadIdentityMismatch => {
                "The isolation backend refused Attach because the policy requests a different workload user or group"
            }
            Self::PolicyProfileMismatch => {
                "The isolation backend refused Attach because the policy does not match its admitted policy profile"
            }
        }
    }

    /// Read the supervisor's bounded refusal reason.
    pub fn from_metadata(metadata: &MetadataMap) -> Result<Option<Self>, Status> {
        let values = metadata.get_all(ATTACH_POLICY_REFUSAL_HEADER);
        let mut values = values.iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(Status::invalid_argument(
                "multiple Attach policy refusal reasons",
            ));
        }
        match value.as_bytes() {
            b"workload-identity-mismatch" => Ok(Some(Self::WorkloadIdentityMismatch)),
            b"policy-profile-mismatch" => Ok(Some(Self::PolicyProfileMismatch)),
            _ => Err(Status::invalid_argument(
                "unknown Attach policy refusal reason",
            )),
        }
    }

    /// Attach the reason to a configuration admission report.
    pub fn write_metadata(self, metadata: &mut MetadataMap) {
        let value = match self {
            Self::WorkloadIdentityMismatch => "workload-identity-mismatch",
            Self::PolicyProfileMismatch => "policy-profile-mismatch",
        };
        metadata.insert(
            ATTACH_POLICY_REFUSAL_HEADER,
            tonic::metadata::MetadataValue::from_static(value),
        );
    }
}
