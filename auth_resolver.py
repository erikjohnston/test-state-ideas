import itertools

from synapse import event_auth
from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError
from synapse.state import _seperate


def resolver(state_sets, event_map):
    unconflicted_state, conflicted_state = _seperate(state_sets)

    auth_diff = _get_auth_chain_difference(state_sets, event_map)
    # print (auth_diff)

    event_id_to_level = [
        (_get_power_level_for_sender(event_id, event_map), event_id)
        for event_id in set(itertools.chain(
            itertools.chain.from_iterable(conflicted_state.values()),
            auth_diff,
        ))
    ]

    event_id_to_level.sort()

    # print(event_id_to_level)

    events_sorted_by_power = [eid for _, eid in event_id_to_level]

    sorted_events = []

    def add_to_list(event_id):
        event = event_map[event_id]

        for aid, _ in event.auth_events:
            if aid in events_sorted_by_power:
                events_sorted_by_power.remove(aid)
                add_to_list(aid)

        sorted_events.append(event_id)

    while events_sorted_by_power:
        ev = events_sorted_by_power.pop()
        add_to_list(ev)

    # print("Sorted_events:")
    # print(" ", sorted_events)

    overridden_state = {}
    event_id_to_auth = {}
    for event_id in sorted_events:
        event = event_map[event_id]
        auth_events = {}
        for aid, _ in event.auth_events:
            aev = event_map[aid]
            auth_events[(aev.type, aev.state_key)] = aev
            for key, eid in overridden_state.items():
                auth_events[key] = event_map[eid]

        try:
            # print("Authing event", event_id, "with auth", auth_events)
            event_auth.check(
                event, auth_events,
                do_sig_check=False,
                do_size_check=False
            )
            allowed = True
            overridden_state[(event.type, event.state_key)] = event_id
        except AuthError:
            allowed = False

        event_id_to_auth[event_id] = allowed

    resolved_state = unconflicted_state

    # print (event_id_to_auth)
    # print (sorted_events)

    for key, conflicted_ids in conflicted_state.items():
        sorted_conflicts = []
        for eid in sorted_events:
            if eid in conflicted_ids:
                sorted_conflicts.append(eid)

        sorted_conflicts.reverse()

        # print (key, sorted_conflicts)

        resolved_eid = sorted_conflicts[-1]
        for eid in sorted_conflicts:
            if event_id_to_auth[eid]:
                resolved_eid = eid
                break

        resolved_state[key] = resolved_eid

    return resolved_state


def _get_power_level_for_sender(event_id, event_map):
    event = event_map[event_id]

    for aid, _ in event.auth_events:
        aev = event_map[aid]
        if aev.type == EventTypes.PowerLevels:
            pl = aev
            break
    else:
        return 0

    level = pl.content.get("users", {}).get(event.sender)
    if level is None:
        level = pl.content.get("users_default", 0)

    if level is None:
        return 0
    else:
        return int(level)


def _get_auth_chain_difference(state_sets, event_map):
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
