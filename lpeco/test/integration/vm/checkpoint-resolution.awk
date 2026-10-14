BEGIN { FS = "\"" }

/"probe_id":/ {
  probe = $4
  next
}

/"status":/ && probe != "" {
  if ($4 == "complete") {
    complete[probe] = 1
  } else {
    incomplete[probe] = 1
  }
  probe = ""
}

END {
  for (probe in incomplete) {
    if (complete[probe]) {
      printf "recovered\t%s\n", probe
    } else {
      printf "unresolved\t%s\n", probe
    }
  }
}
