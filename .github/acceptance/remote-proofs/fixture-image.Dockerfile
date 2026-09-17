FROM docker.io/library/debian@sha256:abc9cb88a5587630d7f915f47b23b0668fe250fbfc6457aa4d52b534c1bbf73f AS fixture

# The input executable is extracted and verified from the shipping image.
COPY --chmod=0555 openshell-supervisor /openshell-supervisor

ENTRYPOINT ["/openshell-supervisor"]
CMD []
