from collections import namedtuple


WalkRow = namedtuple('WalkRow', 'value unfinished')


def group_varbinds(varbinds, base_ids):
    """
    Takes a list of varbinds and a list of base OIDs and returns a mapping from
    those base IDs to lists of varbinds.
    """
    n = len(base_ids)
    results = {}
    for i in range(n):
        results[base_ids[i]] = varbinds[i::n]
    return results


def get_unfinished_walk_oids(grouped_oids, bases=None):
    """
    :param grouped_oids: A dictionary containing VarBinds as values. The keys
        are the base OID of those VarBinds as requested by the user. We need to
        keep track of the base to be able to tell when a walk over OIDs is
        finished (that is, when we hit the first OID outside the base).
    :param bases: ?  TODO
    """
    bases = bases or {}

    # Sometimes (for continued walk requests), the requested OIDs are actually
    # children of the originally requested OIDs on the second and subsequent
    # requests. If *bases* is set, it will contain the originally requested OIDs
    # and we need to replace the dict keys with the appropriate bases.
    if bases:
        new_results = {}
        for k, v in grouped_oids.items():
            containment = [base for base in bases if k in base]
            if len(containment) > 1:
                raise RuntimeError('Unexpected OID result. A value was '
                                   'contained in more than one base than '
                                   'should be possible!')
            if not containment:
                continue
            new_results[containment[0]] = v
            grouped_oids = new_results

    # we now have a list of values for each requested OID and need to determine
    # if we need to continue fetching: Inspect the last item of each list if
    # those OIDs are still children of the requested IDs we need to continue
    # fetching using *those* IDs (as we're using GetNext behaviour). If they are
    # *not* children of the requested OIDs, we went too far (in the case of a
    # bulk operation) and need to remove all outliers.
    #
    # The above behaviour is the same for both bulk and simple operations. For
    # simple operations we simply have a list of 1 element per OID, but the
    # behaviour is identical

    # Build a mapping from the originally requested OID to the last fetched OID
    # from that tree.
    last_received_oids = {k: WalkRow(v[-1], v[-1].oid in k)
                          for k, v in grouped_oids.items()}

    output = [item for item in last_received_oids.items() if item[1].unfinished]
    return output
