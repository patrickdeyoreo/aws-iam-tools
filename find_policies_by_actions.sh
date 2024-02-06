#!/usr/bin/env bash
#
# Find roles and policies with the given actions permitted.

PROGNAME="${0##*/}"
OPTSTRING=":hp:o:av"


################
# Print a helpful message
################
help()
{
    if (($# == 0))
    then
        cat
    else
        head -n 1
    fi
} << EOF
usage: ${PROGNAME} [-h] [-p PROFILE] action [action ...]

Find roles and policies with the given actions permitted.

positional arguments:
  action    Action to find

optional arguments:
  -p        AWS CLI profile name
  -o        Output filename
  -a        Show all policies regardless of role attachment
  -v        Show the role and policy being checked (verbose)
  -h        Show this help message and exit
EOF


################
# Print a one-line usage message
################
usage()
{
    help 1
}


################
# Parse commandline options
################
parse_opts()
{
    OPTIND=1
    OPTARG=""

    local option=""

    while getopts "${OPTSTRING}" option
    do
        case "${option}" in
            "h")
                help
                exit 0
                ;;
            "a")
                show_all=1
                ;;
            "p")
                aws_cmd=("${aws_cmd[@]}" "--profile" "${OPTARG}")
                ;;
            "v")
                verbose=1
                ;;
            "o")
                exec 1>|"${OPTARG}"
                ;;
            "?")
                >&2 printf '%s: -%s: unrecognized option\n' "${PROGNAME}" "${OPTARG}"
                >&2 usage
                exit 2
                ;;
            ":")
                >&2 printf '%s: -%s: missing required argument\n' "${PROGNAME}" "${OPTARG}"
                >&2 usage
                exit 2
                ;;
        esac
    done
}


################
# Return with success (0) if action exists in pattern
################
check_action_in_pattern()
{
    # shellcheck disable=SC2254
    case "$1" in $2) return 0 ;; esac
    return 1
}


################
# Check for actions in inline role policies
################
check_inline_policies()
{
    local role_name
    local policy_name
    local allowed_pattern
    local action

    # Iterate over roles
    while read -r role_name
    do
        if ((verbose))
        then
            >&2 printf '> Checking role %s\n' "${role_name}"
        fi
        # Iterate over inline role policies
        while read -r policy_name
        do
            if ((verbose))
            then
                >&2 printf '==> Checking inline policy %s\n' "${policy_name}"
            fi
            # Iterate over actions allowed by inline role policy
            while read -r allowed_pattern
            do
                # Iterate over user-provided actions
                for action in "$@"
                do
                    # Check if action is allowed by action pattern
                    if check_action_in_pattern "${action}" "${allowed_pattern}"
                    then
                        # Print information on action allowance
                        printf '%s allowed by inline policy %s attached to role %s\n' \
                            "${action}" "${policy_name}" "${role_name}"
                    fi
                done
            done < <(
                "${aws_cmd[@]}" iam get-role-policy \
                    --role-name "${role_name}" --policy-name "${policy_name}" \
                    --query 'PolicyDocument.Statement[?Effect==`Allow`].Action[]' |
                jq --raw-output --compact-output '.[]'
            )
        done < <(
            "${aws_cmd[@]}" iam list-role-policies \
                --role-name "${role_name}" \
                --query 'PolicyNames' |
            jq --raw-output --compact-output '.[]'
        )
    done < <(
        "${aws_cmd[@]}" iam list-roles \
            --query 'Roles[*].RoleName' |
        jq --raw-output --compact-output '.[]'
    )
}


################
# Check for actions in managed policies
################
check_managed_policies()
{
    local policy_arn
    local policy_version
    local allowed_pattern
    local action
    local role_name
    local -a attached_roles=()

    # Iterate over all policies
    while read -r policy_arn
    do
        if ((verbose))
        then
            >&2 printf '> Checking managed policy %s\n' "${policy_arn}"
        fi
        # Get default policy version
        policy_version="$(
            "${aws_cmd[@]}" iam get-policy \
                --policy-arn "${policy_arn}" \
                --query 'Policy.DefaultVersionId' |
            jq --raw-output
        )"
        # Iterate over actions allowed by attached policy
        while read -r allowed_pattern
        do
            # Iterate over user-provided actions
            for action in "$@"
            do
                # Check if action is allowed by action pattern
                if check_action_in_pattern "${action}" "${allowed_pattern}"
                then
                    # Build array of roles to which the policy is attached
                    while read -r role_name
                    do
                        attached_roles+=("${role_name}")
                    done < <(
                        "${aws_cmd[@]}" iam list-entities-for-policy \
                            --policy-arn "${policy_arn}" \
                            --entity-filter 'Role' \
                            --query 'PolicyRoles[*].RoleName' |
                        jq --raw-output --compact-output '.[]'
                    )
                    # Print information on policy and role attachments
                    if test "${#attached_roles[@]}" -gt 1
                    then
                        printf '%s allowed by version %s of policy %s attached to roles ' \
                            "${action}" "${policy_version}" "${policy_arn}"
                        while
                            printf '%s' "${attached_roles[0]}"
                            attached_roles=("${attached_roles[@]:1}")
                            test "${#attached_roles[@]}" -gt 0
                        do
                            if test "${#attached_roles[@]}" -gt 1
                            then
                                printf ', '
                            else
                                printf ' and '
                            fi
                        done
                        echo
                    elif test "${#attached_roles[@]}" -gt 0
                    then
                        printf '%s allowed by version %s of policy %s attached to role %s\n' \
                            "${action}" "${policy_version}" "${policy_arn}" "${attached_roles[0]}"
                    elif ((show_all))
                    then
                        printf '%s allowed by version %s of policy %s attached to no roles\n' \
                            "${action}" "${policy_version}" "${policy_arn}"
                    fi
                fi
            done
        done < <(
            "${aws_cmd[@]}" iam get-policy-version \
                --policy-arn "${policy_arn}" --version-id "${policy_version}" \
                --query 'PolicyVersion.Document.Statement[?Effect==`Allow`].Action[]' |
            jq --raw-output --compact-output '.[]'
        )
    done < <(
        "${aws_cmd[@]}" iam list-policies \
            --query 'Policies[*].Arn' |
        jq --raw-output --compact-output '.[]'
    )
}


################
# Parse options and check for actions allowed in policies
################
main()
{
    local -a aws_cmd=("aws" "--output" "json")
    local -i show_all=0
    local -i verbose=0

    parse_opts "$@"
    shift "$((OPTIND - 1))"

    if (($# == 0))
    then
        >&2 usage
        exit 2
    fi
    
    >&2 printf '* Checking managed policies...\n'
    check_managed_policies "$@"
    >&2 printf '* Checking inline policies...\n'
    check_inline_policies "$@"

    return 0
}


main "$@"