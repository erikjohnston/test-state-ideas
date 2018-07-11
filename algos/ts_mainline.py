"""
TODO
"""
import itertools
import networkx

from synapse import event_auth
from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError


def resolver(state_sets, event_map):
    """Given a set of state return the resolved state.

    Args:
        state_sets(list[dict[tuple[str, str], str]]): A list of dicts from
            type/state_key tuples to event_id
        event_map(dict[str, FrozenEvent]): Map from event_id to event

    Returns:
        dict[tuple[str, str], str]: The resolved state map.
    """

    # First split up the un/conflicted state
    unconflicted_state, conflicted_state = _seperate(state_sets)

    # Also fetch all auth events that appear in only some of the state sets'
    # auth chains.
    auth_diff = _get_auth_chain_difference(state_sets, event_map)

    full_conflicted_set = set(itertools.chain(
        itertools.chain.from_iterable(conflicted_state.values()),
        auth_diff,
    ))

    power_events = (
        eid for eid in full_conflicted_set
        if _is_power_event(event_map[eid])
    )
    sorted_power_events = _reverse_topological_power_sort(
        power_events,
        event_map,
        auth_diff
    )

    resolved_state = _iterative_auth_checks(
        sorted_power_events, unconflicted_state, event_map,
    )

    # OK, so we've now resolved the power events. Now mainline them.

    pl = resolved_state.get((EventTypes.PowerLevels, ""), None)
    leftover_events = (
        ev_id
        for ev_id in full_conflicted_set
        if ev_id not in sorted_power_events
    )

    leftover_events = _mainline_sort(leftover_events, pl, event_map)

    resolved_state = _iterative_auth_checks(
        leftover_events, resolved_state, event_map,
    )

    return resolved_state


def _get_power_level_for_sender(event_id, event_map):
    """Return the power level of the sender of the given event according to
    their auth events.
    """
    event = event_map[event_id]

    for aid, _ in event.auth_events:
        aev = event_map[aid]
        if (aev.type, aev.state_key) == (EventTypes.PowerLevels, ""):
            pl = aev
            break
    else:
        # Check if they're creator
        for aid, _ in event.auth_events:
            aev = event_map[aid]
            if (aev.type, aev.state_key) == (EventTypes.Create, ""):
                if aev.content.get("creator") == event.sender:
                    return 100
                break
        return 0

    level = pl.content.get("users", {}).get(event.sender)
    if level is None:
        level = pl.content.get("users_default", 0)

    if level is None:
        return 0
    else:
        return int(level)


def _get_auth_chain_difference(state_sets, event_map):
    """Compare the auth chains of each state set and return the set of events
    that only appear in some but not all of the auth chains.
    """
    auth_sets = []
    for state_set in state_sets:
        auth_ids = set(
            eid
            for key, eid in state_set.items()
            if key[0] in (
                 EventTypes.Member,
                 EventTypes.ThirdPartyInvite,
            ) or key in (
                (EventTypes.PowerLevels, ''),
                (EventTypes.Create, ''),
                (EventTypes.JoinRules, ''),
            )
        )

        while True:
            added = False
            for aid in set(auth_ids):
                to_add = set(eid for eid, _ in event_map[aid].auth_events)
                if to_add - auth_ids:
                    added = True
                    auth_ids.update(to_add)

            if not added:
                break

        auth_sets.append(auth_ids)

    intersection = set(auth_sets[0]).intersection(*auth_sets[1:])
    union = set().union(*auth_sets)

    return union - intersection


def _seperate(state_sets):
    """Return the unconflicted and conflicted state. This is different than in
    the original algorithm, as this defines a key to be conflicted if one of
    the state sets doesn't have that key.
    """
    unconflicted_state = {}
    conflicted_state = {}

    for key in set(itertools.chain.from_iterable(state_sets)):
        event_ids = set(state_set.get(key) for state_set in state_sets)
        if len(event_ids) == 1:
            unconflicted_state[key] = event_ids.pop()
        else:
            conflicted_state[key] = set(eid for eid in event_ids if eid)

    return unconflicted_state, conflicted_state


def _is_auth_event(key):
    if key[0] in (EventTypes.Member, EventTypes.ThirdPartyInvite):
        return True

    return key in (
        (EventTypes.PowerLevels, ""),
        (EventTypes.JoinRules, ""),
        (EventTypes.Create, ""),
    )


def _is_power_event(event):
    if (event.type, event.state_key) in (
        (EventTypes.PowerLevels, ""),
        (EventTypes.JoinRules, ""),
        (EventTypes.Create, ""),
    ):
        return True

    if event.type == EventTypes.Member:
        if event.membership in ('leave', 'ban'):
            return event.sender != event.state_key

    return False


def window(seq, n=2):
    "Returns a sliding window (of width n) over data from the iterable"
    "   s -> (s0,s1,...s[n-1]), (s1,s2,...,sn), ...                   "
    it = iter(seq)
    result = tuple(itertools.islice(it, n))
    if len(result) == n:
        yield result
    for elem in it:
        result = result[1:] + (elem,)
        yield result


def _add_event_and_auth_chain_to_graph(graph, event_id, event_map, auth_diff):
    graph.add_node(event_id)

    state = [event_id]
    while state:
        eid = state.pop()
        for aid, _ in event_map[event_id].auth_events:
            if aid in auth_diff and aid not in graph:
                graph.add_edge(eid, aid)
                state.append(aid)


def _reverse_topological_power_sort(event_ids, event_map, auth_diff):
    graph = networkx.DiGraph()
    for event_id in event_ids:
        _add_event_and_auth_chain_to_graph(
            graph, event_id, event_map, auth_diff,
        )

    def _get_power_order(event_id):
        ev = event_map[event_id]
        pl = _get_power_level_for_sender(event_id, event_map)
        # FIXME: we should be taking the reverse event_id
        return pl, -ev.origin_server_ts, event_id

    it = networkx.algorithms.dag.lexicographical_topological_sort(
        graph,
        key=_get_power_order,
    )
    sorted_events = list(it)
    sorted_events.reverse()

    return sorted_events


def _iterative_auth_checks(event_ids, base_state, event_map):
    resolved_state = base_state.copy()

    for event_id in event_ids:
        event = event_map[event_id]

        auth_events = {
            (event_map[aid].type, event_map[aid].state_key): event_map[aid]
            for aid, _ in event.auth_events
        }
        for key in event_auth.auth_types_for_event(event):
            if key in resolved_state:
                auth_events[key] = event_map[resolved_state[key]]

        try:
            event_auth.check(
                event, auth_events,
                do_sig_check=False,
                do_size_check=False
            )

            resolved_state[(event.type, event.state_key)] = event_id
        except AuthError:
            pass

    return resolved_state


def _mainline_sort(event_ids, resolved_power_event_id, event_map):
    mainline = []
    pl = resolved_power_event_id
    while pl:
        mainline.append(pl)
        auth_events = event_map[pl].auth_events
        pl = None
        for aid, _ in auth_events:
            ev = event_map[aid]
            if (ev.type, ev.state_key) == (EventTypes.PowerLevels, ""):
                pl = aid
                break

    mainline.reverse()

    mainline_map = {ev_id: i + 1 for i, ev_id in enumerate(mainline)}

    def get_mainline_depth(event_id):
        if event_id in mainline_map:
            return mainline_map[event_id]

        ev = event_map[event_id]
        if not ev.auth_events:
            return 0

        depth = max(
            get_mainline_depth(aid)
            for aid, _ in ev.auth_events
        )

        return depth

    event_ids = list(event_ids)

    order_map = {
        ev_id: (
            get_mainline_depth(ev_id),
            event_map[ev_id].origin_server_ts,
            ev_id,
        )
        for ev_id in event_ids
    }

    event_ids.sort(key=lambda ev_id: order_map[ev_id])

    return event_ids
