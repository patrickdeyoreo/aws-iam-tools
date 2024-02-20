#!/usr/bin/env bash
#
# Destroy and restore IAM roles.
#
# usage: delete_roles         [-h] [-n] [-v] [-o OUTPUT] [-p PROFILE] SUBCOMMAND
#        delete_roles destroy [-h] [-a] [-c] [-i] [-b DIRNAME] [-x PATTERN] FILE ...
#        delete_roles restore [-h] [-c] DIRECTORY

set -e

__progname__="${0##*/}"

__subcommands__=(
    "destroy"
    "restore"
)

__global_optstr__=":hnvo:p:"
__global_usage__="${__progname__} [-h] [-n] [-v] [-o OUTPUT] [-p PROFILE] SUBCOMMAND"

__destroy_optstr__=":hacib:x:"
__destroy_usage__="${__progname__} [OPTIONS] destroy [-h] [-a] [-c] [-i] [-b DIRNAME] [-x PATTERN] FILE ..."

__restore_optstr__=":hc"
__restore_usage__="${__progname__} [OPTIONS] restore [-h] [-c] DIRECTORY"

# shellcheck disable=SC1078,SC1079
__global_help__="""\
usage: ${__global_usage__}

Destroy and restore AWS IAM roles.

subcommands:
  destroy        Destroy IAM roles, reading role names or ARNs line-by-line
  restore        Restore deleted IAM roles from a backup directory

optional arguments:
  -n            Do not do anything - only show roles that would be affected
  -o FILE       Write results to a file
  -p PROFILE    Use given AWS CLI profile
  -v            Show each action being taken (verbose)
  -h            Show this help message and exit"""

# shellcheck disable=SC1078,SC1079
__destroy_help__="""\
usage: ${__destroy_usage__}

Destroy IAM roles, reading role names or ARNs line-by-line.

positional arguments:
  OPTIONS       Global options (see \`${__progname__} -h\`)
  FILE          Name of a file from which to read roles names or ARNs

optional arguments:
  -a            Delete AWS-managed roles (*DANGEROUS - CANNOT BE UNDONE*)
  -c            Confirm before destroying a role
  -b DIRNAME    Backup deleted roles to a directory (can be used by 'restore' subcommand)
  -i            Delete instance profiles after detaching roles
  -x PATTERN    Exclude role names matching a pattern (extended regexp, like egrep)
  -h            Show this help message and exit"""

# shellcheck disable=SC1078,SC1079
__restore_help__="""\
usage: ${__restore_usage__}

Restore deleted IAM roles from a backup directory.

positional arguments:
  OPTIONS       Global options (see \`${__progname__} -h\`)
  DIRECTORY     Name of a directory from which to restore roles

optional arguments:
  -c            Confirm before restoring a role
  -h            Show this help message and exit"""


################
# Print if ``verbose'' is enabled 
################
printf_verbose()
{
    if ((verbose))
    then
        # shellcheck disable=SC2059
        printf "$@"
    fi
}


################
# Check if a subcommand is recognized
################
is_subcommand()
{
    local subcommand

    for subcommand in "${__subcommands__[@]}"
    do
        if test "$1" == "${subcommand}"
        then
            return 0
        fi
    done
    return 1
}


################
# Print a helpful message
################
help()
{
    local help_name=""

    if (($# == 0))
    then
        help_name="__global_help__"
        printf '%s\n' "${!help_name}"
    elif is_subcommand "$1"
    then
        help_name="__${1}_help__"
        printf '%s\n' "${!help_name}"
    else
        return 1
    fi
}


################
# Print a usage message
################
usage()
{
    local usage_name=""

    if (($# == 0))
    then
        usage_name="__global_usage__"
        printf 'usage: %s\n' "${!usage_name}"
    elif is_subcommand "$1"
    then
        usage_name="__${1}_usage__"
        printf 'usage: %s\n' "${!usage_name}"
    else
        return 1
    fi
}


################
# Parse commandline options
################
parse_opts()
{
    OPTIND=1

    local opt=""

    while getopts "${__global_optstr__}" opt
    do
        case "${opt}" in
            "h")
                help
                exit 0
                ;;
            "n")
                dry_run=1
                ;;
            "o")
                exec 1> "${OPTARG}"
                ;;
            "p")
                aws_cmd+=("--profile" "${OPTARG}")
                ;;
            "v")
                verbose+=1
                ;;
            "?")
                >&2 printf '%s: -%s: unrecognized option\n' "${__progname__}" "${OPTARG}"
                >&2 usage
                exit 2
                ;;
            ":")
                >&2 printf '%s: -%s: missing required argument\n' "${__progname__}" "${OPTARG}"
                >&2 usage
                exit 2
                ;;
        esac
    done

    if ! (($#))
    then
        >&2 usage
        exit 2
    fi

    subcommand="${!OPTIND}"
    OPTIND=$((OPTIND + 1))

    if ! is_subcommand "${subcommand}"
    then
        >&2 printf '%s: %s: unrecognized subcommand\n' "${__progname__}" "${subcommand}"
        >&2 usage
        exit 2
    fi
    "__parse_opts_${subcommand}" "$@"
}



################
# Parse ``destroy'' commandline options
################
__parse_opts_destroy()
{
    local opt=""

    while getopts "${__destroy_optstr__}" opt
    do
        case "${opt}" in
            "h")
                help destroy
                exit 0
                ;;
            "a")
                delete_aws_roles=1
                ;;
            "b")
                backups=1
                backups_dir="${OPTARG}"
                ;;
            "c")
                confirm=1
                ;;
            "i")
                delete_instance_profiles=1
                ;;
            "x")
                regexps+=("-e" "${OPTARG}")
                ;;
            "?")
                >&2 printf '%s: -%s: unrecognized option\n' "${__progname__}" "${OPTARG}"
                >&2 usage destroy
                exit 2
                ;;
            ":")
                >&2 printf '%s: -%s: missing required argument\n' "${__progname__}" "${OPTARG}"
                >&2 usage destroy
                exit 2
                ;;
        esac
    done
    shift  "$((OPTIND - 1))"

    if ! (($#))
    then
        >&2 usage destroy
        exit 2
    fi
}


################
# Parse ``restore'' commandline options
################
__parse_opts_restore()
{
    local opt=""

    while getopts "${__restore_optstr__}" opt
    do
        case "${opt}" in
            "h")
                help restore
                exit 0
                ;;
            "c")
                confirm=1
                ;;
            "?")
                >&2 printf '%s: -%s: unrecognized option\n' "${__progname__}" "${OPTARG}"
                >&2 usage restore
                exit 2
                ;;
            ":")
                >&2 printf '%s: -%s: missing required argument\n' "${__progname__}" "${OPTARG}"
                >&2 usage restore
                exit 2
                ;;
        esac
    done
    shift  "$((OPTIND - 1))"

    if ! (($#))
    then
        >&2 usage restore
        exit 2
    fi
    if (($# > 1))
    then
        >&2 printf '%s: too many arguments\n' "${__progname__}"
        >&2 usage restore
        exit 2
    fi
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
# Setup a new backup directory, renaming any existing directory and replacing it
################
setup_new_backup_dir()
{
    local -i bkp_num=1

    # Rename existing backup directory
    if test -d "${backups_dir}"
    then
        while test -a "${backups_dir}.${bkp_num}"
        do
            bkp_num+=1
        done

        >&2 printf_verbose '* Renaming existing backup directory %s to %s\n' "${backups_dir}" "${backups_dir}.${bkp_num}"

        if ! mv -- "${backups_dir}" "${backups_dir}.${bkp_num}"
        then
            >&2 printf '%s: %s: could not rename existing backup directory\n' "${__progname__}" "${backups_dir}"
            exit 1
        fi
    fi

    >&2 printf_verbose '* Creating new backup directory %s\n' "${backups_dir}"

    # Create new backup directory
    if ! mkdir -p -- "${backups_dir}"
    then
        >&2 printf '%s: %s: could not create new backup directory\n' "${__progname__}" "${backups_dir}"
        exit 1
    fi

    >&2 printf_verbose '* Checking permissions on backup directory %s\n' "${backups_dir}"

    # Check permissions on backup directory
    if ! {
        test -r "${backups_dir}" &&
        test -w "${backups_dir}" &&
        test -x "${backups_dir}"
    }
    then
        >&2 printf '%s: %s: insufficient permissions on backup directory\n' "${__progname__}" "${backups_dir}"
        exit 1
    fi
}


################
# Remove role from instance profile
################
remove_role_from_instance_profiles()
{
    local instance_profile
    local instance_profile_backups_dir="${backups_dir}/$1/instance_profiles"

    # Create instance profile backup directory
    if ((backups)) && ! mkdir -- "${instance_profile_backups_dir}"
    then
        >&2 printf '* Failed to create instance profile backup directory %s\n' "${instance_profile_backups_dir}"
        return 1
    fi

    # Iterate over instance profiles
    while read -r -u 3 instance_profile
    do
        >&2 printf_verbose '==> Removing role from instance profile %s\n' "${instance_profile}"

        # Backup instance profile attachment
        if ((backups))
        then
            printf '%s\n' "${instance_profile}" >> "${instance_profile_backups_dir}/attachments"
        fi

        # Detach instance profile
        if ! "${aws_cmd[@]}" iam remove-role-from-instance-profile --instance-profile-name "${instance_profile}" --role-name "$1" > /dev/null
        then
            >&2 printf '*** Failed to remove role from instance profile %s\n' "${instance_profile}"
            return 1
        fi
        printf 'Removed role from instance profile %s\n' "${instance_profile}"

        if ((delete_instance_profiles))
        then
            >&2 printf_verbose '==> Deleting instance profile %s\n' "${instance_profile}"
        else
            continue
        fi

        # Backup instance profile
        if ((backups))
        then
            >&2 printf_verbose '==> Backing up instance profile to %s\n' "${instance_profile_backups_dir}/${instance_profile}.json"
            "${aws_cmd[@]}" iam get-instance-profile --instance-profile-name "${instance_profile}" --query 'InstanceProfile' |
            jq 'with_entries(select(.key == ("Path", "Tags")))' >> "${instance_profile_backups_dir}/${instance_profile}.json"
        fi

        # Delete instance profile
        if ! "${aws_cmd[@]}" iam delete-instance-profile --instance-profile-name "${instance_profile}" > /dev/null
        then
            >&2 printf '*** Failed to delete instance profile %s\n' "${instance_profile}"
            continue
        fi
        printf 'Deleted instance profile %s\n' "${instance_profile}"

    done 3< <(
        "${aws_cmd[@]}" iam list-instance-profiles-for-role --role-name "$1" --query 'InstanceProfiles[*].InstanceProfileName' |
        jq --raw-output --compact-output '.[]'
    )
    return 0
}


################
# Destroy inline role policies
################
delete_inline_role_policies()
{
    local policy
    local inline_policy_backups_dir="${backups_dir}/$1/inline_policies"

    # Create inline role policy backup directory
    if ((backups)) && ! mkdir -- "${inline_policy_backups_dir}"
    then
        >&2 printf '* Failed to create inline policy backup directory %s\n' "${inline_policy_backups_dir}"
        return 1
    fi

    # Iterate over inline role policies
    while read -r -u 3 policy
    do
        >&2 printf_verbose '==> Deleting inline role policy %s\n' "${policy}"

        # Backup inline policy
        if ((backups))
        then
            >&2 printf_verbose '==> Backing up inline policy to %s\n' "${inline_policy_backups_dir}/${policy}.json"
            "${aws_cmd[@]}" iam get-role-policy --role-name "$1" --policy-name "${policy}" |
            jq 'with_entries(select(.key == ("PolicyDocument")))' >> "${inline_policy_backups_dir}/${policy}.json"
        fi

        # Delete inline policy
        if ! "${aws_cmd[@]}" iam delete-role-policy --role-name "$1" --policy-name "${policy}" > /dev/null
        then
            >&2 printf '*** Failed to delete inline policy %s\n' "${policy}"
            return 1
        fi
        printf 'Deleted inline policy %s\n' "${policy}"

    done 3< <(
        "${aws_cmd[@]}" iam list-role-policies --role-name "$1" --query 'PolicyNames' |
        jq --raw-output --compact-output '.[]'
    )
    return 0
}


################
# Detach managed role policies
################
detach_managed_role_policies()
{
    local policy
    local managed_policy_backups_dir="${backups_dir}/$1/managed_policies"

    # Create managed role policy backup directory
    if ((backups)) && ! mkdir -- "${managed_policy_backups_dir}"
    then
        >&2 printf '* Failed to create managed policy backup directory %s\n' "${managed_policy_backups_dir}"
        return 1
    fi

    # Iterate over managed role policies
    while read -r -u 3 policy
    do
        >&2 printf_verbose '==> Detaching managed policy %s\n' "${policy}"

        # Backup managed policy attachment
        if ((backups))
        then
            printf '%s\n' "${policy}" >> "${managed_policy_backups_dir}/attachments"
        fi

        # Detach managed policy
        if ! "${aws_cmd[@]}" iam detach-role-policy --role-name "$1" --policy-arn "${policy}" > /dev/null
        then
            >&2 printf '*** Failed to detach managed policy %s\n' "${policy}"
            return 1
        fi
        printf 'Detached managed policy %s\n' "${policy}"

    done 3< <(
        "${aws_cmd[@]}" iam list-attached-role-policies --role-name "$1" --query 'AttachedPolicies[*].PolicyArn' |
        jq --raw-output --compact-output '.[]'
    )
    return 0
}


################
# Destroy a role
################
delete_role()
{
    >&2 printf_verbose '==> Deleting role %s\n' "$1"

    # Backup role
    if ((backups))
    then
        >&2 printf_verbose '==> Backing up role to %s\n' "${backups_dir}/$1/role.json"
        "$("${aws_cmd[@]}" iam get-role --role-name "$1" --query "Role")" |
        jq 'with_entries(select(.key == ("Path", "RoleName", "AssumeRolePolicyDocument", "Description", "MaxSessionDuration", "PermissionsBoundary", "Tags")))' > "${backups_dir}/$1/role.json"
    fi

    # Delete role
    if ! "${aws_cmd[@]}" iam delete-role --role-name "$1" > /dev/null
    then
        >&2 printf '*** Failed to delete role %s\n' "$1"
        return 1
    fi
    printf 'Deleted role %s\n' "${role}"
    return 0
}


################
# Check if a role exists
################
role_exists()
{
    >&2 printf_verbose '==> Checking if role %s exists\n' "$1"

    if ! "${aws_cmd[@]}" iam get-role --role-name "$1" > /dev/null 2>&1
    then
        return 1
    fi
    return 0
}


################
# Restore instance profiles
################
restore_instance_profiles()
{
    local data_file
    local instance_profile_name

    if ! test -d "$1/instance_profiles"
    then
        return 1
    fi

    for data_file in "$1"/instance_profiles/*.json
    do
        if test -a "${data_file}"
        then
            instance_profile_name="${data_file##*/}"
            instance_profile_name="${instance_profile_name%.json}"

            "${aws_cmd[@]}" iam create-instance-profile \
                --instance-profile-name "${instance_profile_name}" \
                --cli-input-json "$(< "${data_file}")"
        fi
    done

    if test -a "$1/instance_profiles/attachments"
    then
        while read -r -u 3 instance_profile_name
        do
            "${aws_cmd[@]}" iam add-role-to-instance-profile \
                --instance-profile-name "${instance_profile_name}" \
                --role-name "${1##*/}"
        done 3< "$1/instance_profiles/attachments"
    fi
}


################
# Restore managed role policies
################
restore_managed_role_policies()
{
    local policy_arn

    if ! test -d "$1/managed_policies"
    then
        return 1
    fi

    if test -a "$1/managed_policies/attachments"
    then
        while read -r -u 3 policy_arn
        do
            "${aws_cmd[@]}" iam attach-role-policy \
                --role-name "${1##*/}" \
                --policy-arn "${policy_arn}"
        done 3< "$1/managed_policies/attachments"
    fi
}


################
# Restore inline role policies
################
restore_inline_role_policies()
{
    local data_file
    local policy_name

    if ! test -d "$1/inline_policies"
    then
        return 1
    fi

    for data_file in "$1"/inline_policies/*.json
    do
        if test -a "${data_file}"
        then
            policy_name="${data_file##*/}"
            policy_name="${policy_name%.json}"

            "${aws_cmd[@]}" iam put-role-policy \
                --role-name "${1##*/}" \
                --policy-name "${policy_name}" \
                --policy-document "$(jq ".PolicyDocument" < "${data_file}")" \
                --cli-input-json "$(< "${data_file}")"
        fi
    done
}


################
# Restore a role
################
restore_role()
{
    if ! test -f "$1/role.json"
    then
        return 1
    fi

    "${aws_cmd[@]}" iam create-role \
        --role-name "${1##*/}" \
        --assume-role-policy-document "$(jq ".AssumeRolePolicyDocument" < "$1/role.json")" \
        --cli-input-json "$(< "$1/role.json")"
}


################
# Destroy roles read line-by-line from files
################
destroy()
{
    local line=""
    local role
    local role_path

    if ((backups))
    then
        setup_new_backup_dir
    fi
    # Iterate over all policies
    while
        if test -n "${line}"
        then
            sleep 0.25
            >&2 echo
        fi
        read -r -u 3 line
    do
        >&2 printf_verbose '> %s\n' "${line}"

        case "${line}" in
            "")
                continue
                ;;
            arn:aws:iam::*:role/*)
                role="${line#arn:aws:iam::*:role/}"
                ;;
            arn:aws:*:*:*:*)
                >&2 printf '* ARN %s does not refer to an IAM role - skipping\n' "${line}"
                continue
                ;;
            role/*)
                role="${line#role/}"
                ;;
            *)
                role="${line}"
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

        if ((${#regexps[@]})) && grep -E --line-regexp "${regexps[@]}" <<< "${role}"
        then
            >&2 printf '* Role %s matches an exclude-pattern - skipping\n' "${role}"
            continue
        fi

        if ! role_exists "${role}"
        then
            >&2 printf '* Role %s does not exist - skipping\n' "${role}"
            continue
        fi

        if ((dry_run))
        then
            printf 'Would destroy role %s\n' "${role}"
            continue
        fi

        if ((confirm)) && ! confirm "Destroy role ${role}?"
        then
            continue
        fi

        >&2 printf 'Destroying role %s\n' "${role}"

        if ((backups)) && ! mkdir -- "${backups_dir}/${role}"
        then
            >&2 printf '* Failed to create role backup directory %s - skipping\n' "${backups_dir}/$1"
            continue
        fi
        if
            remove_role_from_instance_profiles "${role}" &&
            delete_inline_role_policies "${role}" &&
            detach_managed_role_policies "${role}" &&
            delete_role "${role}"
        then
            >&2 printf 'Success destroying role %s\n' "${role}"
        else
            >&2 printf 'Failure destroying role %s\n' "${role}"
        fi

    done 3< <(cat -- "$@")

    return 0
}


################
# Restore deleted roles from backup directory
################
restore()
{
    local path
    local role

    # Check that directory exists
    if ! test -d "$1"
    then
        >&2 printf '%s: %s: no such directory\n' "${__progname__}" "$1"
        exit 2
    fi

    # Iterate over subdirectories (roles)
    for path in "$1"/*
    do
        if test -n "${role}"
        then
            sleep 0.25
            >&2 echo
        fi

        if test -a "${path}"
        then
            >&2 printf_verbose '> %s\n' "${path}"

            if ((dry_run))
            then
                printf 'Would restore role %s\n' "${role}"
                continue
            fi

            if ((confirm)) && ! confirm "Restore role ${role}?"
            then
                continue
            fi

            >&2 printf 'Restoring role %s\n' "${path##*/}"
            if
                restore_role "${path}" &&
                restore_inline_role_policies "${path}" &&
                restore_managed_role_policies "${path}" &&
                restore_instance_profiles "${path}"
            then
                >&2 printf 'Success restoring role %s\n' "${role}"
            else
                >&2 printf 'Failure restoring role %s\n' "${role}"
            fi
        fi
    done
}


################
# Parse options and execute role operation
################
main()
{
    local subcommand=""
    local aws_cmd=("aws" "--output" "json")
    local -i backups=0
    local -i confirm=0
    local -i delete_aws_roles=0
    local -i delete_instance_profiles=0
    local -i dry_run=0
    local -i verbose=0
    local regexps=()
    local backups_dir=""

    parse_opts "$@"

    if ((verbose > 1))
    then
        printf '=============================\n'
        printf '+ AWS CLI command:          %s\n' "${aws_cmd[*]}"
        printf '+ Backups:                  %s\n' "${backups}"
        printf '+ Backup directory:         %s\n' "${backups_dir}"
        printf '+ Confirm operations:       %s\n' "${confirm}"
        printf '+ Delete AWS-managed roles: %s\n' "${delete_aws_roles}"
        printf '+ Delete instance profiles: %s\n' "${delete_instance_profiles}"
        printf '+ Dry-run:                  %s\n' "${dry_run}"
        printf '=============================\n'
        echo
    fi >&2
    shift "$((OPTIND - 1))"

    "${subcommand}" "$@"
}


main "$@"
