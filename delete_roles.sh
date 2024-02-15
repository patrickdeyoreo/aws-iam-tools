#!/usr/bin/env bash
#
# Delete IAM roles
#
# Usage: delete_roles.sh [-h] [FILE ...]

PROGNAME="${0##*/}"
OPTSTR=":hacivo:p:"


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
usage: ${PROGNAME} [-h] [-aciv] [-o OUTPUT] [-p PROFILE] [FILE ...]

Delete IAM roles, reading role names or ARNs line-by-line.

positional arguments:
  FILE          Name of a file from which to read roles names or ARNs

optional arguments:
  -a            Delete AWS-managed roles (*DANGEROUS*)
  -c            Confirm before deleting
  -i            Delete instance profiles after detaching roles
  -o OUTPUT     Output filename
  -p PROFILE    AWS CLI profile name
  -v            Show each action being taken (verbose)
  -h            Show this help message and exit
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

    local opt=""

    while getopts "${OPTSTR}" opt
    do
        case "${opt}" in
            "h")
                help
                exit 0
                ;;
            "a")
                delete_aws_roles=1
                ;;
            "c")
                confirm_deletion=1
                ;;
            "i")
                delete_instance_profiles=1
                ;;
            "o")
                exec 1>|"${OPTARG}"
                ;;
            "p")
                profile="${OPTARG}"
                aws_cmd=("${aws_cmd[@]}" "--profile" "${profile}")
                ;;
            "v")
                verbose=1
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
# Confirm yes or no
################
confirm()
{
    local response
    while
        >&2 printf '%s(y/n) ' "${1:+$1 }"
        read -r response
    do
        case "${response}" in
            Y|y|YES|Yes|yes)
                return 0
                ;;
            N|n|NO|No|no)
                return 1
                ;;
        esac
    done
    return 1
}


################
# Remove role from instance profile
################
remove_role_from_instance_profiles()
{
    local instance_profile

    while read -r instance_profile
    do
        if ((verbose))
        then
            >&2 printf '==> Removing role from instance profile %s\n' "${instance_profile}"
        fi
        if ! "${aws_cmd[@]}" iam remove-role-from-instance-profile --instance-profile-name "${instance_profile}" --role-name "$1"
        then
            >&2 printf '*** Failed to remove role from instance profile %s\n' "${instance_profile}"
            return 1
        fi

        if ! ((delete_instance_profiles))
        then
            continue
        fi

        if ((verbose))
        then
            >&2 printf '==> Deleting instance profile %s\n' "${instance_profile}"
        fi
        if ! "${aws_cmd[@]}" iam delete-instance-profile --instance-profile-name "${instance_profile}"
        then
            >&2 printf '*** Failed to delete instance profile %s\n' "${instance_profile}"
        fi
    done < <(
        "${aws_cmd[@]}" iam list-instance-profiles-for-role --role-name "$1" --query 'InstanceProfiles[*].InstanceProfileName' |
        jq --raw-output --compact-output '.[]'
    )
}


################
# Delete inline role policies
################
delete_inline_role_policies()
{
    local policy

    while read -r policy
    do
        if ((verbose))
        then
            >&2 printf '==> Deleting inline role policy %s\n' "${policy}"
        fi
        if ! "${aws_cmd[@]}" iam delete-role-policy --role-name "$1" --policy-name "${policy}"
        then
            >&2 printf '*** Failed to delete inline role policy %s\n' "${policy}"
            return 1
        fi
    done < <(
        "${aws_cmd[@]}" iam list-role-policies --role-name "$1" --query 'PolicyNames' |
        jq --raw-output --compact-output '.[]'
    )
}


################
# Detach managed role policies
################
detach_managed_role_policies()
{
    local policy

    while read -r policy
    do
        if ((verbose))
        then
            >&2 printf '==> Detaching managed policy %s\n' "${policy}"
        fi
        if ! "${aws_cmd[@]}" iam detach-role-policy --role-name "$1" --policy-arn "${policy}"
        then
            >&2 printf '*** Failed to detach managed policy %s\n' "${policy}"
            return 1
        fi
    done < <(
        "${aws_cmd[@]}" iam list-attached-role-policies --role-name "$1" --query 'AttachedPolicies[*].PolicyArn' |
        jq --raw-output --compact-output '.[]'
    )
}


################
# Delete a role
################
delete_role()
{
    if ((verbose))
    then
        >&2 printf '==> Deleting role %s\n' "$1"
    fi
    if ! "${aws_cmd[@]}" delete-role --role-name "$1"
    then
        >&2 printf '*** Failed to delete role %s\n' "$1"
        return 1
    fi
}


################
# Check if a role exists
################
role_exists()
{
    if ((verbose))
    then
        >&2 printf '==> Checking if role %s exists\n' "$1"
    fi
    if ! "${aws_cmd[@]}" get-role --role-name "$1" 1> /dev/null 2>&1
    then
        return 1
    fi
    return 0

}

################
# Delete roles read line-by-line from files
################
delete_roles()
{
    local line
    local role
    local role_path

    # Iterate over all policies
    while read -r -u 3 line
    do
        case "${line}" in
            arn:aws:iam::*:role/*)
                role="${role#arn:aws:iam::*:role/}"
                ;;
            arn:aws:*:*:*:*)
                >&2 printf '* ARN %s does not refer to an IAM role - skipping\n' "${line}"
                continue
                ;;
            "")
                continue
                ;;
        esac
        case "${role}" in
            */*)
                role_path="${role%/*}"
                role="${role##*/}"
                ;;
            *)
                role_path=""
                ;;
        esac
        case "${role_path}" in
            aws-*)
                if ! ((delete_aws_roles))
                then
                    >&2 printf '* Role %s is an AWS-managed role - skipping\n' "${role}"
                    continue
                fi
                ;;
        esac

        if ((confirm_deletion))
        then
            confirm "Delete role ${role}?" || continue
        fi

        >&2 printf '> Operating on role %s\n' "${role}"

        if {
            remove_role_from_instance_profiles "${role}" &&
            delete_inline_role_policies "${role}" &&
            detach_managed_role_policies "${role}" &&
            delete_role "${role}"
        }
        then
            printf 'Deleted %s\n' "${line}"
        else
            printf 'Failed to delete %s\n' "${line}"
        fi

    done 3< <(cat -- "$@")
}


################
# Parse options and run role deletion
################
main()
{
    local aws_cmd=("aws" "--output" "json")
    local profile="default"
    local -i delete_aws_roles=0
    local -i confirm_deletion=0
    local -i delete_instance_profiles=0
    local -i verbose=0

    parse_opts "$@"
    shift "$((OPTIND - 1))"

    >&2 printf '* Using AWS CLI profile %s\n' "${profile}"

    delete_roles "$@"

    return 0
}


main "$@"
