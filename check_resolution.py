"""Program that interprets graph description yaml files.

Currently supported modes:
    render: outputs a dotfile of the graph
    resolve: tests a given state resolution algorithm against the given graph
"""

import argparse
import importlib
import itertools
import yaml

from networkx import DiGraph, topological_sort
from synapse import event_auth
from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.api.errors import AuthError
from synapse.events import FrozenEvent
from synapse.types import UserID, EventID, RoomID, get_localpart_from_id
from tabulate import tabulate


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


SERVER_NAME = "example.com"


def to_user_id(s):
    return UserID(s, SERVER_NAME).to_string()


def to_room_id(s):
    return RoomID(s, SERVER_NAME).to_string()


def to_event_id(s):
    return EventID(s, SERVER_NAME).to_string()


INITIAL_EVENTS = {
    "CREATE": {
        "type": EventTypes.Create,
        "state_key": "",
        "sender": "alice",
        "content": {"creator": to_user_id("alice")},
    },
    "IMA": {
        "type": EventTypes.Member,
        "state_key": "alice",
        "sender": "alice",
        "content": {"membership": Membership.JOIN},
    },
    "IPOWER": {
        "type": EventTypes.PowerLevels,
        "state_key": "",
        "sender": "alice",
        "content": {"users": {"alice": 100}},
    },
    "IJR": {
        "type": EventTypes.JoinRules,
        "state_key": "",
        "sender": "alice",
        "content": {"join_rule": JoinRules.PUBLIC},
    },
    "IMB": {
        "type": EventTypes.Member,
        "state_key": "bob",
        "sender": "bob",
        "content": {"membership": Membership.JOIN},
    },
    "IMC": {
        "type": EventTypes.Member,
        "state_key": "charlie",
        "sender": "charlie",
        "content": {"membership": Membership.JOIN},
    },
    "IMZ": {
        "type": EventTypes.Member,
        "state_key": "zara",
        "sender": "zara",
        "content": {"membership": Membership.JOIN},
    },
    "START": {
        "type": EventTypes.Message,
        "sender": "zara",
        "content": {},
    },
    "END": {
        "type": EventTypes.Message,
        "sender": "zara",
        "content": {},
    },
}

EDGES = ("START", "IMZ", "IMC", "IMB", "IJR", "IPOWER", "IMA", "CREATE",)
AUTH_EVENTS = {
    "CREATE": [],
    "IMA": ["CREATE"],
    "IPOWER": ["CREATE", "IMA"],
    "IJR": ["CREATE", "IMA", "IPOWER"],
    "IMB": ["CREATE", "IJR", "IPOWER"],
    "IMC": ["CREATE", "IJR", "IPOWER"],
    "IMZ": ["CREATE", "IJR", "IPOWER"],
    "START": ["CREATE", "IMZ", "IPOWER"],
    "END": ["CREATE", "IMZ", "IPOWER"],
}

ROOM_ID = to_room_id("room")


def create_dag(graph_desc):
    """Takes a graph description and returns DiGraph's

    Returns
        (DiGraph, DiGraph, dict[str, FrozenEvent]): A tuple of room DAG, auth
        DAG and event map.
    """

    edge_map = {}
    auth_events = dict(AUTH_EVENTS)

    for start, end in pairwise(EDGES):
        edge_map.setdefault(start, set()).add(end)

    for edges in graph_desc["edges"]:
        for start, end in pairwise(edges):
            edge_map.setdefault(start, set()).add(end)

    for eid, aids in graph_desc["auth"].items():
        auth_events[eid] = ["CREATE"] + aids

    event_map = {}

    for eid, event in itertools.chain(
        INITIAL_EVENTS.items(),
        graph_desc["events"].items(),
    ):
        event = dict(event)
        event["sender"] = to_user_id(event["sender"])

        if event.get("state_key", "") != "":
            event["state_key"] = to_user_id(event["state_key"])

        if event["type"] == EventTypes.PowerLevels:
            new_users = {}
            for u, pl in event["content"].get("users", {}).items():
                new_users[to_user_id(u)] = pl

            event["content"] = dict(event["content"])
            event["content"]["users"] = new_users

        event["event_id"] = to_event_id(eid)
        event["prev_events"] = [
            (to_event_id(e), "") for e in edge_map.get(eid, [])
        ]
        event["auth_events"] = [
            (to_event_id(e), "") for e in auth_events.get(eid, [])
        ]
        event["room_id"] = ROOM_ID

        event["depth"] = 0

        event_map[to_event_id(eid)] = FrozenEvent(event)

    event_graph = DiGraph()
    for eid, prev_ids in edge_map.items():
        event_graph.add_edges_from(
            (to_event_id(eid), to_event_id(pid))
            for pid in prev_ids
        )

    auth_graph = DiGraph()
    for eid, auth_ids in auth_events.items():
        auth_graph.add_edges_from(
            (to_event_id(eid), to_event_id(pid))
            for pid in auth_ids
        )

    return event_graph, auth_graph, event_map


def resolve(graph_desc, resolution_func):
    """Given graph description and state resolution algorithm, compute the end
    state of the graph and compare against the expected state defined in the
    graph description
    """

    graph, _, event_map = create_dag(graph_desc)

    state_past_event = {}
    for eid in reversed(list(topological_sort(graph))):
        event = event_map[eid]

        prev_states = []
        for pid, _ in event.prev_events:
            prev_states.append(state_past_event[pid])

        state_ids = {}
        if len(prev_states) == 1:
            state_ids = prev_states[0]
        elif len(prev_states) > 1:
            state_ids = resolver_func(
                prev_states, event_map,
            )

        auth_events = {
            key: event_map[state_ids[key]]
            for key in event_auth.auth_types_for_event(event)
            if key in state_ids
        }

        try:
            event_auth.check(
                event, auth_events,
                do_sig_check=False, do_size_check=False,
            )
        except AuthError as e:
            print("Failed to auth event", eid, " because:", e)
            return

        if event.is_state():
            state_ids = dict(state_ids)
            state_ids[(event.type, event.state_key)] = eid

        state_past_event[eid] = state_ids

    end_state = state_past_event[to_event_id("END")]

    expected_state = {}
    for eid in graph_desc["expected_state"]:
        ev = event_map[to_event_id(eid)]
        expected_state[(ev.type, ev.state_key)] = to_event_id(eid)

    mismatches = []
    for key, expected_id in expected_state.items():
        if end_state[key] != expected_id:
            mismatches.append((key[0], key[1], expected_id, end_state[key]))

    if mismatches:
        print("Unexpected end state\n")
        print(tabulate(
            mismatches,
            headers=["Type", "State Key", "Expected", "Got"],
        ))
    else:
        print("Everything matched!")


def render(graph_desc, render_auth_events):
    """Given graph description prints a dot file of the graph.

    Args:
        graph_desc (dict)
        render_auth_events (bool): Whether to render the auth event relations
            as edges
    """
    event_graph, auth_graph, event_map = create_dag(graph_desc)

    from graphviz import Digraph

    graph = Digraph()
    graph.attr(rankdir="TB")
    graph.attr(concentrate="true")

    with graph.subgraph(name='cluster_main') as c:
        c.attr(color='red')
        for eid, ev in event_map.items():
            nid = get_localpart_from_id(eid)

            attrs = {}
            if nid in graph_desc["expected_state"]:
                attrs["style"] = "bold"
                attrs["color"] = "green"
                attrs["peripheries"] = "2"
            elif "state_key" not in ev:
                attrs["style"] = "dashed"
                attrs["color"] = "grey"
                attrs["fontcolor"] = "grey"

            if nid in graph_desc["events"]:
                c.node(nid, **attrs)
            else:
                graph.node(nid, **attrs)

    for start, end in event_graph.edges:
        start = get_localpart_from_id(start)
        end = get_localpart_from_id(end)
        graph.edge(start, end)

    if render_auth_events:
        for start, end in auth_graph.edges:
            start = get_localpart_from_id(start)
            end = get_localpart_from_id(end)
            if end != "CREATE":
                graph.edge(start, end, color="blue", constraint="false")

    print(graph.source)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command")

    parser_resolve = subparsers.add_parser('resolve')
    parser_resolve.add_argument("resolver")
    parser_resolve.add_argument(
        "files", nargs='+', type=argparse.FileType('r'),
    )

    parser_render = subparsers.add_parser('render')
    parser_render.add_argument("file", type=argparse.FileType('r'))
    parser_render.add_argument("-a", "--auth-events", action="store_true")

    args = parser.parse_args()

    if args.command == "resolve":
        module, func_name = args.resolver.rsplit(".", 1)
        module = importlib.import_module(module)
        resolver_func = getattr(module, func_name)

        for f in args.files:
            graph_desc = yaml.load(f)

            print("Resolving", f.name)
            resolve(graph_desc, resolver_func)
    elif args.command == "render":
        graph_desc = yaml.load(args.file)
        render(graph_desc, args.auth_events)
