plan tlsinfo::cfssl (
  TargetSpec $targets,
) {
  run_plan(facts, $targets)

  return apply($targets) {
    include tlsinfo

    class { 'tlsinfo::tools::cfssl': }
  }
}
