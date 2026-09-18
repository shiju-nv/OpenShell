# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Uses the candidate's locked dependencies and unchanged cross-linker constructor.
# Selecting one toolchain avoids realizing all four cross sysroots on a small runner.
{ source, target ? builtins.currentSystem }:
let
  flake = builtins.getFlake (toString source);
  pkgs = import flake.inputs.nixpkgs {
    system = builtins.currentSystem;
    overlays = [ (import flake.inputs.rust-overlay) ];
  };
  selected = if target == "x86_64-unknown-linux-musl" then pkgs.pkgsCross.musl64
    else if builtins.currentSystem == "x86_64-linux" then pkgs.pkgsCross.gnu64
    else if builtins.currentSystem == "aarch64-linux" then pkgs.pkgsCross.aarch64-multiplatform
    else throw "Only standard Linux x64/ARM runners are supported";
  buildInputs = { pkgs, stdenv }: [
    (pkgs.callPackage (source + "/nix/pkgs/z3.nix") { inherit stdenv; })
    (pkgs.callPackage (source + "/nix/pkgs/aws-lc.nix") { inherit stdenv; })
  ];
  toolchain = (import (source + "/nix/toolchain")).mkToolchain {
    pkgs = selected;
    inherit buildInputs;
  };
  rust = (pkgs.rust-bin.fromRustupToolchainFile (source + "/rust-toolchain.toml")).override {
    targets = [ toolchain.target ];
    extensions = [ "clippy" ];
  };
in pkgs.mkShellNoCC {
  packages = with pkgs; [
    rust cargo-deny cargo-nextest cargo-auditable e2fsprogs pkg-config
    git dpkg actionlint uv yq-go zstd fish ripgrep perl
  ];
  env = toolchain.env;
}
