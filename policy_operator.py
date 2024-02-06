#!/usr/bin/env python3
"""
Given a policy, operate on it.

Supported operations are `condense` and `list-services`.
"""
import argparse
import copy
import enum
import json
import signal
import sys
import os
from typing import Any, Dict, List, Union

PROGNAME = os.path.basename(__file__)


class Effect(str, enum.Enum):
    """
    Represent a policy statement effect.
    """
    ALLOW = "Allow"
    DENY = "Deny"

    @classmethod
    def values(cls) -> List[str]:
        """
        Get enum values.
        """
        return list(effect.value for effect in Effect.__members__.values())


class Action:
    """
    Represent a policy statement action.
    """
    service: str
    action: str

    def __init__(self, service: str, action: str):
        """
        Initialize an action.
        """
        self.service, self.action = service, action

    @classmethod
    def from_str(cls, action: str):
        """
        Initialize an action.
        """
        return cls(*action.split(":", maxsplit=1))

    def __str__(self) -> str:
        """
        Stringify an action.
        """
        return f"{self.service}:{self.action}"

    def copy(self):
        """
        Copy an action.
        """
        return Action(self.service, self.action)

    def words(self) -> List[str]:
        """
        Get the words of an action.
        """
        if self.action.isupper() or self.action.islower():
            words = [self.action]
        else:
            words = []
            start = 0
            index = 1
            while index < len(self.action):
                if self.action[index].isupper() or self.action[index] == "*":
                    words.append(self.action[start:index])
                    start = index
                index += 1
            words.append(self.action[start:])
        return words


class Statement:
    """
    Represent a policy statement.
    """
    sid: Union[str, None]
    effect: Effect
    actions: Union[Action, List[Action]]
    resources: Union[str, List[str]]
    principals: Union[
        Dict[str, Union[str, List[str]]], None]
    conditions: Union[
        Dict[str, Dict[str, Union[str, List[str]]]], None]

    def __init__(self,
                 sid: Union[str, None],
                 effect: Effect,
                 actions: Union[Action, List[Action]],
                 resources: Union[str, List[str]],
                 principals: Union[
                     Dict[str, Union[str, List[str]]], None],
                 conditions: Union[
                     Dict[str, Dict[str, Union[str, List[str]]]], None]):
        """
        Initialize a statement.
        """
        self.sid = sid
        self.effect = Effect(effect.value)
        if isinstance(actions, Action):
            self.actions = actions.copy()
        else:
            self.actions = [action.copy() for action in actions]
        if isinstance(resources, str):
            self.resources = resources
        else:
            self.resources = resources.copy()
        if principals is None:
            self.principals = None
        else:
            self.principals = copy.deepcopy(principals)
        if conditions is None:
            self.conditions = None
        else:
            self.conditions = copy.deepcopy(conditions)

    @classmethod
    def from_dict(cls, statement: Dict[str, Any]):
        """
        Create a statement from a dict.
        """
        sid = statement.get("Sid")
        if sid is not None and not isinstance(sid, str):
            raise TypeError(f"Sid must be of type {str}: "
                            f"got {type(sid)}")

        try:
            effect = Effect(statement["Effect"])
        except KeyError as exc:
            raise ValueError("Statement missing key: Effect") from exc
        except ValueError as exc:
            effect_values = ", ".join(Effect.values())
            raise ValueError(f"Effect must be one of {effect_values}: "
                             f"got {statement['Effect']}") from exc

        try:
            actions = statement["Action"]
        except KeyError as exc:
            raise ValueError("Statement missing key: Action") from exc
        if not isinstance(actions, (str, list)):
            raise TypeError(f"Action must be of type {str} or {list}: "
                            f"got {type(actions)}")
        if isinstance(actions, str):
            actions = Action.from_str(actions)
        else:
            actions = list(map(Action.from_str, actions))

        try:
            resources = statement["Resource"]
        except KeyError as exc:
            raise ValueError("Statement missing key: Resource") from exc
        if not isinstance(resources, (str, list)):
            raise TypeError(f"Resource must be of type {str} or {list}: "
                            f"got {type(resources)}")

        principals = statement.get("Principal")
        if principals is not None and not isinstance(principals, dict):
            raise TypeError(f"Principal must be of type {dict}: "
                            f"got {type(principals)}")

        conditions = statement.get("Condition")
        if conditions is not None and not isinstance(conditions, dict):
            raise TypeError(f"Condition must be of type {dict}: "
                            f"got {type(conditions)}")

        return cls(sid=sid,
                   effect=effect,
                   actions=actions,
                   resources=resources,
                   principals=principals,
                   conditions=conditions)

    def __str__(self) -> str:
        """
        Stringify a statement.
        """
        return json.dumps(self.to_dict(), indent=4)

    def copy(self):
        """
        Copy a statement.
        """
        return type(self)(sid=self.sid,
                          effect=self.effect,
                          actions=self.actions,
                          resources=self.resources,
                          principals=self.principals,
                          conditions=self.conditions)

    def to_dict(self) -> dict:
        """
        Dictify a statement.
        """
        statement = {}

        if self.sid is not None:
            statement["Sid"] = self.sid

        statement["Effect"] = self.effect.value

        if isinstance(self.actions, Action):
            statement["Action"] = str(self.actions)
        else:
            statement["Action"] = list(map(str, self.actions))

        if isinstance(self.resources, str):
            statement["Resource"] = self.resources
        else:
            statement["Resource"] = self.resources.copy()

        if self.principals is not None:
            statement["Principal"] = copy.deepcopy(self.principals)

        if self.conditions is not None:
            statement["Condition"] = copy.deepcopy(self.conditions)

        return statement

    def get_services(self, sort: bool = False) -> List[str]:
        """
        Get a list of all services in the statement.
        """
        if isinstance(self.actions, list):
            services = list(set(action.service for action in self.actions))
        else:
            services = [self.actions.service]
        if sort:
            services.sort()

        return services

    def get_condensed(self, sort: bool = False) -> Union[Action, List[Action]]:
        """
        Condense actions by longest prefixes.
        """
        if isinstance(self.actions, Action):
            condensed = self.actions.copy()
        else:
            condensed = []

            # Construct map from services to lists of action words
            service_action_words = {}
            for action in self.actions:
                if action.service in service_action_words:
                    service_action_words[action.service].append(action.words())
                else:
                    service_action_words[action.service] = [action.words()]

            # Find action patterns to add to condensed action list
            for service, action_words in service_action_words.items():

                # Iterate over all actions for a service
                action_words.sort(key=lambda words: words[0])
                start, stop = 0, 1
                while start < len(action_words):

                    # Find bounds of actions with common first word
                    first_word = action_words[start][0]
                    shortest = len(action_words[start])
                    while (stop < len(action_words) and
                           action_words[stop][0] == first_word):
                        if len(action_words[stop]) < shortest:
                            shortest = len(action_words[stop])
                        stop += 1

                    # Find longest prefix of actions with common first word
                    action_index = start
                    word_index = 1
                    while word_index < shortest:
                        word = action_words[start][word_index]
                        while action_index < stop:
                            if action_words[action_index][word_index] == word:
                                action_index += 1
                            else:
                                break
                        if action_index == stop:
                            action_index = start
                            word_index += 1
                        else:
                            break

                    # Add action pattern to condensed list of actions
                    common_prefix = ''.join(action_words[start][:word_index])
                    if stop - start == 1:
                        condensed.append(Action(service, common_prefix))
                    else:
                        condensed.append(Action(service, common_prefix + "*"))

                    # Continue from next action
                    start = stop

        # Return a new statement with condensed action patterns
        if sort:
            condensed.sort(key=str)

        return type(self)(sid=self.sid,
                          effect=self.effect,
                          actions=condensed,
                          resources=self.resources,
                          principals=self.principals,
                          conditions=self.conditions)


class Policy:
    """
    Represent a policy.
    """
    version: str
    statements: List[Statement]

    def __init__(self, version: str, statements: List[Statement]):
        """
        Initialize a policy.
        """
        self.version = version
        self.statements = [statement.copy() for statement in statements]

    @classmethod
    def from_dict(cls, policy: Dict[str, Any]):
        """
        Create a policy from a dictionary.
        """
        try:
            version = policy["Version"]
        except KeyError as exc:
            raise ValueError("Policy missing key: Version") from exc
        if not isinstance(version, str):
            raise TypeError(f"Version must be of type {str}: "
                            f"got {type(version)}")

        try:
            statements = policy["Statement"]
        except KeyError as exc:
            raise ValueError("Policy missing key: Statement") from exc
        if not isinstance(statements, list):
            raise TypeError(f"Statement must be of type {list}: "
                            f"got {type(statements)}")

        statements_from_dict = []
        for statement in statements:
            try:
                statements_from_dict.append(Statement.from_dict(statement))
            except (TypeError, ValueError) as exc:
                sid = statement.get('Sid')
                sid = "(nil)" if sid is None else f"'{sid}'"
                raise ValueError(f"Sid {sid}: "
                                 f"{exc}") from exc

        return cls(version=version,
                   statements=statements_from_dict)

    def __str__(self) -> str:
        """
        Render a policy as json.
        """
        return json.dumps(self.to_dict(), indent=4)

    def to_dict(self) -> dict:
        """
        Dictify a policy.
        """
        return {
            "Version": self.version,
            "Statement": [statement.to_dict() for statement in self.statements]
        }

    def get_condensed(self, sort: bool = False) -> dict:
        """
        Condense actions of each statement by longest prefixes.
        """
        return type(self)(version=self.version,
                          statements=[statement.get_condensed(sort=sort)
                                      for statement in self.statements])

    def get_services(self, sort: bool = False) -> list:
        """
        Return a list of all services listed in the policy
        """
        services = list(set(service
                            for statement in self.statements
                            for service in statement.get_services(sort=sort)))
        if sort:
            services.sort()

        return services


def condense(policy: Policy, args: argparse.Namespace) -> dict:
    """
    Get a condensed version of the policy.
    """
    return policy.get_condensed(sort=args.sort).to_dict()


def list_services(policy: Policy, args: argparse.Namespace) -> list:
    """
    Get a list of all services referenced by the policy.
    """
    return policy.get_services(sort=args.sort)


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o", "--output",
        type=argparse.FileType("w", encoding="utf-8"),
        default="-",
        help="Name of the file in which to write output")

    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-s",
        "--sort",
        action='store_true',
        help="Sort actions and services"
    )
    common_parser.add_argument(
        "file",
        type=argparse.FileType("r", encoding="utf-8"),
        nargs="?",
        default='-',
        help="Name of the file from which to read a policy",
        metavar="FILENAME")

    subparsers = parser.add_subparsers(
        title='subcommands',
        help='Operation to perform on the policy'
    )

    parser_condense = subparsers.add_parser(
        'condense',
        parents=[common_parser],
        description=condense.__doc__)
    parser_condense.set_defaults(func=condense)

    parser_services = subparsers.add_parser(
        'list-services',
        parents=[common_parser],
        description=list_services.__doc__)
    parser_services.set_defaults(func=list_services)

    return parser.parse_args()


def main() -> None:
    """
    Condense a policy.
    """
    args = parse_args()
    try:
        data = json.load(args.file)
    except json.JSONDecodeError:
        print(f"{PROGNAME}: {args.file.name}: Invalid JSON", file=sys.stderr)
        sys.exit(1)
    if not isinstance(data, dict):
        print(f"{PROGNAME}: {args.file.name}: Not a policy", file=sys.stderr)
        sys.exit(1)
    try:
        json.dump(args.func(Policy.from_dict(data), args),
                  args.output,
                  indent=4)
        args.output.write('\n')
    except Exception as err:
        print(f"{PROGNAME}: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(128 + signal.SIGINT)
