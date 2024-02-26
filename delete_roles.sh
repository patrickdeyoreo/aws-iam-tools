#!/usr/bin/env bash
#
# Destroy and restore IAM roles.
#
# usage: delete_roles         [-h] [-n] [-v] [-o OUTPUT] [-p PROFILE] SUBCOMMAND
#        delete_roles destroy [-h] [-c] [-a] [-i] [-b DIRNAME] [-x PATTERN] FILE ...
#        delete_roles restore [-h] [-c] DIRECTORY

set -e

exec 4>&1

trap '
>&2 echo
exit 130
' SIGINT

__progname__="${0##*/}"

__subcommands__=(
    "destroy"
    "restore"
)

__global_optstr__=":hnvo:p:"
__global_usage__="${__progname__} [-h] [-n] [-v] [-o OUTPUT] [-p PROFILE] SUBCOMMAND"

__global_help__="usage: ${__global_usage__}

Destroy and restore AWS IAM roles.

subcommands:
  destroy        Destroy IAM roles, reading role names or ARNs line-by-line
  restore        Restore deleted IAM roles from a backup directory

optional arguments:
  -n            Do not do anything - only show roles that would be affected
  -o FILE       Write results to a file
  -p PROFILE    Use given AWS CLI profile
  -v            Show each action being taken (verbose)
  -h            Show this help message and exit"

__destroy_optstr__=":hacib:x:"
__destroy_usage__="${__progname__} [OPTIONS] destroy [-h] [-c] [-a] [-i] [-b DIRNAME] [-x PATTERN] FILE ..."

__destroy_help__="usage: ${__destroy_usage__}

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
  -h            Show this help message and exit"

__restore_optstr__=":hc"
__restore_usage__="${__progname__} [OPTIONS] restore [-h] [-c] DIRECTORY"

__restore_help__=" usage: ${__restore_usage__}

Restore deleted IAM roles from a backup directory.

positional arguments:
  OPTIONS       Global options (see \`${__progname__} -h\`)
  DIRECTORY     Name of a directory from which to restore roles

optional arguments:
  -c            Confirm before restoring a role
  -h            Show this help message and exit"


################
# Print if verbosity is at or above given level.
#
# usage: log LEVEL ARGS...
################
log()
{
    local level

    level=$(($1))
    shift

    if ((verbose >= level))
    then
        # shellcheck disable=SC2059
        printf "$@"
    fi
}


################
# Confirm yes or no.
#
# usage: confirm
################
confirm()
{
    local response

    while
        >&2 log 0 '%s(y/n) ' "${1:+$1 }"
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
# Check if a subcommand is recognized.
#
# usage: is_subcommand SUBCOMMAND
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
# Print a helpful message.
#
# usage: help [SUBCOMMAND]
################
function help()
{
    local help_name=""

    if ! (($#))
    then
        log 0 '%s\n' "${__global_help__}"
    elif is_subcommand "$1"
    then
        help_name="__${1}_help__"
        log 0 '%s\n' "${!help_name}"
    else
        return 1
    fi
}


################
# Print a usage message.
#
# usage: usage [SUBCOMMAND]
################
usage()
{
    local usage_name=""

    if ! (($#))
    then
        log 0 'usage: %s\n' "${__global_usage__}"
    elif is_subcommand "$1"
    then
        usage_name="__${1}_usage__"
        log 0 'usage: %s\n' "${!usage_name}"
    else
        return 1
    fi
}


################
# Parse commandline options.
#
# usage: parse_opts
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
                exec 4> "${OPTARG}"
                ;;
            "p")
                profile="${OPTARG}"
                aws_cmd+=("--profile" "${OPTARG}")
                ;;
            "v")
                verbose+=1
                ;;
            "?")
                >&2 log 0 '%s: -%s: unrecognized option\n' "${__progname__}" "${OPTARG}"
                >&2 usage
                exit 2
                ;;
            ":")
                >&2 log 0 '%s: -%s: missing required argument\n' "${__progname__}" "${OPTARG}"
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
        >&2 log 0 '%s: %s: unrecognized subcommand\n' "${__progname__}" "${subcommand}"
        >&2 usage
        exit 2
    fi
    "__parse_opts_${subcommand}" "$@"
}



################
# Parse ``destroy'' subcommand options.
#
# usage: __parse_opts_destroy
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
                backup_dir="${OPTARG}"
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
                >&2 log 0 '%s: -%s: unrecognized option\n' "${__progname__}" "${OPTARG}"
                >&2 usage destroy
                exit 2
                ;;
            ":")
                >&2 log 0 '%s: -%s: missing required argument\n' "${__progname__}" "${OPTARG}"
                >&2 usage destroy
                exit 2
                ;;
        esac
    done
    shift "$((OPTIND - 1))"

    if ! (($#))
    then
        >&2 usage destroy
        exit 2
    fi
}


################
# Parse ``restore'' subcommand options.
#
# usage: __parse_opts_restore
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
                >&2 log 0 '%s: -%s: unrecognized option\n' "${__progname__}" "${OPTARG}"
                >&2 usage restore
                exit 2
                ;;
            ":")
                >&2 log 0 '%s: -%s: missing required argument\n' "${__progname__}" "${OPTARG}"
                >&2 usage restore
                exit 2
                ;;
        esac
    done
    shift "$((OPTIND - 1))"

    if ! (($# == 1))
    then
        >&2 usage restore
        exit 2
    fi
}


################
# Create a new backup directory, renaming any existing directory.
#
# usage: create_backup_dir DIRECTORY
################
create_backup_dir()
{
    local -i bkp_num=1

    # Rename existing backup directory
    if test -d "$1"
    then
        while test -a "$1.${bkp_num}"
        do
            bkp_num+=1
        done
        >&2 log 1 'Renaming existing backup directory %s to %s\n' "$1" "$1.${bkp_num}"

        if ! mv -- "$1" "$1.${bkp_num}"
        then
            >&2 log 0 '%s: %s: could not rename existing backup directory\n' "${__progname__}" "$1"
            exit 1
        fi
    fi

    # Create new backup directory
    >&2 log 1 'Creating new backup directory %s\n' "$1"

    if ! mkdir -p -- "$1"
    then
        >&2 log 0 '%s: %s: could not create new backup directory\n' "${__progname__}" "$1"
        exit 1
    fi

    # Back up list of existing roles
    >&2 log 1 'Backing up list of existing roles to %s\n' "$1/roles.json"

    if ! "${aws_cmd[@]}" iam list-roles --query 'Roles[*].{RoleName: RoleName, RoleId: RoleId, AssumeRolePolicyDocument: AssumeRolePolicyDocument}' > "$1/roles.json"
    then
        >&2 log 0 '%s: %s: failed to back up list of existing roles\n' "${__progname__}" "$1/roles.json"
        exit 1
    fi
}


################
# Check for required top-level contents of backup directory.
#
# usage: check_backup_dir DIRECTORY
################
check_backup_dir()
{
    # Check for backup directory
    >&2 log 1 'Checking for backup directory %s\n' "$1"

    if ! test -d "$1"
    then
        >&2 log 0 '%s: %s: no such directory\n' "${__progname__}" "$1"
        exit 1
    fi

    # Check permissions on backup directory
    >&2 log 2 'Checking permissions on backup directory %s\n' "$1"

    if ! { test -r "$1" && test -w "$1" && test -x "$1"; }
    then
        >&2 log 0 '%s: %s: insufficient permissions\n' "${__progname__}" "$1"
        exit 1
    fi

    # Check for global roles backup file
    >&2 log 1 'Checking for global roles backup file %s\n' "$1/roles.json"

    if ! test -f "$1/roles.json"
    then
        >&2 log 0 '%s: %s: missing required file\n' "${__progname__}" "$1/roles.json"
        exit 1
    fi

    # Check permissions on global roles backup file
    >&2 log 2 'Checking permissions on global roles backup file %s\n' "$1/roles.json"

    if ! test -r "$1/roles.json"
    then
        >&2 log 0 '%s: %s: insufficient permissions\n' "${__progname__}" "$1/roles.json"
        exit 1
    fi
}


################
# Check if a role exists.
#
# usage: role_exists ROLE_NAME
################
role_exists()
{
    >&2 log 1 '==> Checking if role %s exists\n' "$1"

    if ! "${aws_cmd[@]}" iam get-role --role-name "$1" > /dev/null 2>&1
    then
        return 1
    fi
}


################
# Check if an instance profile exists.
#
# usage: instance_profile_exists INSTANCE_PROFILE_NAME
################
instance_profile_exists()
{
    >&2 log 1 '==> Checking if instance profile %s exists\n' "$1"

    if ! "${aws_cmd[@]}" iam get-instance-profile --instance-profile-name "$1" > /dev/null 2>&1
    then
        return 1
    fi
}


################
# Remove role from instance profile.
#
# usage: remove_role_from_instance_profiles ROLE_NAME INSTANCE_PROFILE_BACKUP_DIR
################
remove_role_from_instance_profiles()
{
    local instance_profile

    # Iterate over instance profiles
    while read -r -u 3 instance_profile
    do
        # Backup instance profile mapping
        if ((backups))
        then
            if ! echo -E "${instance_profile}" >> "$2/instance_profiles.txt"
            then
                >&2 log 1 '*** Failed to back up role mapping to instance profile %s\n' "${instance_profile}"
                >&4 log 0 'Failed to back up role mapping from role %s to instance profile %s\n' "$1" "${instance_profile}"
                return 1
            fi
        fi

        # Remove role from instance profile
        >&2 log 1 '==> Removing role from instance profile %s\n' "${instance_profile}"

        if "${aws_cmd[@]}" iam remove-role-from-instance-profile --instance-profile-name "${instance_profile}" --role-name "$1" > /dev/null
        then
            >&4 log 0 'Removed role %s from instance profile %s\n' "$1" "${instance_profile}"
        else
            >&2 log 1 '*** Failed to remove role from instance profile %s\n' "${instance_profile}"
            >&4 log 0 'Failed to remove role %s from instance profile %s\n' "$1" "${instance_profile}"
            return 1
        fi

        if ! ((delete_instance_profiles))
        then
            continue
        fi

        # Backup instance profile
        if ((backups))
        then
            >&2 log 1 '==> Backing up instance profile to %s\n' "$2/${instance_profile}.json"
            if ! {
                "${aws_cmd[@]}" iam get-instance-profile --instance-profile-name "${instance_profile}" --query 'InstanceProfile' |
                jq 'with_entries(select(.key == ("Path", "Tags")))' > "$2/${instance_profile}.json"
            }
            then
                >&2 log 1 '*** Failed to back up instance profile %s\n' "${instance_profile}"
                >&4 log 0 'Failed to back up instance profile %s\n' "${instance_profile}"
                return 1
            fi
        fi

        # Delete instance profile
        >&2 log 1 '==> Deleting instance profile %s\n' "${instance_profile}"

        if "${aws_cmd[@]}" iam delete-instance-profile --instance-profile-name "${instance_profile}" > /dev/null
        then
            >&4 log 0 'Deleted instance profile %s\n' "${instance_profile}"
        else
            >&2 log 1 '*** Failed to delete instance profile %s\n' "${instance_profile}"
            >&4 log 0 'Failed to delete instance profile %s\n' "${instance_profile}"
            return 1
        fi

    done 3< <(
        "${aws_cmd[@]}" iam list-instance-profiles-for-role --role-name "$1" --query 'InstanceProfiles[*].InstanceProfileName' |
        jq --raw-output --compact-output '.[]'
    )
}


################
# Detach managed role policies.
#
# usage: detach_managed_role_policies ROLE_NAME MANAGED_POLICY_BACKUP_DIR
################
detach_managed_role_policies()
{
    local policy

    # Iterate over managed role policies
    while read -r -u 3 policy
    do
        # Backup managed policy attachment
        if ((backups))
        then
            if ! echo -E "${policy}" >> "$2/managed_policies.txt"
            then
                >&2 log 1 '*** Failed to back up attachment of managed policy %s\n' "${policy}"
                >&4 log 0 'Failed to back up attachment of managed policy %s to role %s\n' "${policy}" "$1"
                return 1
            fi
        fi

        # Detach managed policy
        >&2 log 1 '==> Detaching managed policy %s\n' "${policy}"

        if "${aws_cmd[@]}" iam detach-role-policy --role-name "$1" --policy-arn "${policy}" > /dev/null
        then
            >&4 log 0 'Detached managed policy %s from role %s\n' "${policy}" "$1"
        else
            >&2 log 1 '*** Failed to detach managed policy %s\n' "${policy}"
            >&4 log 0 'Failed to detach managed policy %s from role %s\n' "${policy}" "$1"
            return 1
        fi

    done 3< <(
        "${aws_cmd[@]}" iam list-attached-role-policies --role-name "$1" --query 'AttachedPolicies[*].PolicyArn' |
        jq --raw-output --compact-output '.[]'
    )
}


################
# Destroy inline role policies.
#
# usage: delete_inline_role_policies ROLE_NAME INLINE_POLICY_BACKUP_DIR
################
delete_inline_role_policies()
{
    local policy

    # Iterate over inline role policies
    while read -r -u 3 policy
    do
        # Backup inline policy
        if ((backups))
        then
            >&2 log 1 '==> Backing up inline policy to %s\n' "$2/${policy}.json"
            if ! {
                "${aws_cmd[@]}" iam get-role-policy --role-name "$1" --policy-name "${policy}" |
                jq 'with_entries(select(.key == ("PolicyDocument")))' > "$2/${policy}.json"
            }
            then
                >&2 log 1 '*** Failed to back up inline policy %s\n' "${policy}"
                >&4 log 0 'Failed to back up inline policy %s of role %s\n' "${policy}" "$1"
                return 1
            fi
        fi

        # Delete inline policy
        >&2 log 1 '==> Deleting inline role policy %s\n' "${policy}"

        if "${aws_cmd[@]}" iam delete-role-policy --role-name "$1" --policy-name "${policy}" > /dev/null
        then
            >&4 log 0 'Deleted inline policy %s from role %s\n' "${policy}" "$1"
        else
            >&2 log 1 '*** Failed to delete inline policy %s\n' "${policy}"
            >&4 log 0 'Failed to delete inline policy %s from role %s\n' "${policy}" "$1"
            return 1
        fi

    done 3< <(
        "${aws_cmd[@]}" iam list-role-policies --role-name "$1" --query 'PolicyNames' |
        jq --raw-output --compact-output '.[]'
    )
}


################
# Destroy a role.
#
# usage: delete_role ROLE_NAME ROLE_BACKUP_DIR
################
delete_role()
{
    # Backup role
    if ((backups))
    then
        >&2 log 1 '==> Backing up role to %s\n' "$2/role.json"
        if ! {
            "${aws_cmd[@]}" iam get-role --role-name "$1" --query "Role" |
            jq 'with_entries(select(.key == ("Path", "RoleName", "Description", "MaxSessionDuration", "PermissionsBoundary", "Tags")))' > "$2/role.json"
        }
        then
            >&2 log 1 '*** Failed to back up role %s\n' "$1"
            >&4 log 0 'Failed to back up role %s\n' "$1"
            return 1
        fi
    fi

    # Delete role
    >&2 log 1 '==> Deleting role %s\n' "$1"

    if "${aws_cmd[@]}" iam delete-role --role-name "$1" > /dev/null
    then
        >&4 log 0 'Deleted role %s\n' "$1"
    else
        >&2 log 1 '*** Failed to delete role %s\n' "$1"
        >&4 log 0 'Failed to delete role %s\n' "$1"
        return 1
    fi
}


################
# Restore instance profiles.
#
# usage: restore_instance_profiles ROLE_NAME INSTANCE_PROFILE_BACKUP_DIR
################
restore_instance_profiles()
{
    local data_file
    local instance_profile_name

    # Check if instance profile backup directory exists
    if ! test -d "$2"
    then
        >&2 log 1 '*** No instance profile backup directory %s for role %s\n' "$2" "$1"
        >&4 log 0 'No instance profile backup directory %s for role %s\n' "$2" "$1"
        return 1
    fi

    # Create instance profiles
    >&2 log 1 '==> Restoring instance profiles\n'

    for data_file in "$2"/*.json
    do
        if test -a "${data_file}"
        then
            instance_profile_name="${data_file##*/}"
            instance_profile_name="${instance_profile_name%.json}"

            if ! instance_profile_exists "${instance_profile_name}"
            then
                # Create instance profile
                >&2 log 1 '==> Creating instance profile %s\n' "${instance_profile_name}"

                if "${aws_cmd[@]}" iam create-instance-profile --instance-profile-name "${instance_profile_name}" --cli-input-json "$(< "${data_file}")" > /dev/null
                then
                    >&4 log 0 'Created instance profile %s\n' "${instance_profile_name}"
                else
                    >&2 log 1 '*** Failed to create instance profile %s\n' "${instance_profile}"
                    >&4 log 0 'Failed to create instance profile %s\n' "${instance_profile}"
                    return 1
                fi
            else
                >&2 log 1 '*** Instance profile %s already exists - continuing\n' "${instance_profile_name}"
                >&4 log 0 'Instance profile %s already exists\n' "${instance_profile_name}"
            fi
        fi
    done

    # Restore instance profile mappings
    >&2 log 1 '==> Adding role to instance profiles\n'

    if test -a "$2/instance_profiles.txt"
    then
        while read -r -u 3 instance_profile_name
        do
            # Add role to instance profile
            >&2 log 1 '==> Adding role to instance profile %s\n' "${instance_profile_name}"

            if "${aws_cmd[@]}" iam add-role-to-instance-profile --instance-profile-name "${instance_profile_name}" --role-name "$1" > /dev/null
            then
                >&4 log 0 'Added role %s to instance profile %s\n' "$1" "${instance_profile_name}"
            else
                >&2 log 1 '*** Failed to add role to instance profile %s\n' "${instance_profile}"
                >&4 log 0 'Failed to add role %s to instance profile %s\n' "$1" "${instance_profile}"
                return 1
            fi
        done 3< "$2/instance_profiles.txt"
    fi
}


################
# Restore managed role policies.
#
# usage: restore_managed_role_policies ROLE_NAME MANAGED_POLICY_BACKUP_DIR
################
restore_managed_role_policies()
{
    local policy_arn

    # Check if managed policy backup directory exists
    if ! test -d "$2"
    then
        >&2 log 1 '*** No managed policy backup directory %s for role %s\n' "$2" "$1"
        >&4 log 0 'No managed policy backup directory %s for role %s\n' "$2" "$1"
        return 1
    fi

    # Attach managed policies
    >&2 log 1 '==> Restoring managed policy attachments\n'

    if test -a "$2/managed_policies.txt"
    then
        while read -r -u 3 policy_arn
        do
            # Attach managed policy
            >&2 log 1 '==> Attaching managed policy %s\n' "${policy_arn}"

            if "${aws_cmd[@]}" iam attach-role-policy --role-name "$1" --policy-arn "${policy_arn}" > /dev/null
            then
                >&4 log 0 'Attached managed policy %s to role %s\n' "${policy_arn}" "$1"
            else
                >&2 log 1 '*** Failed to attach managed policy %s\n' "${policy_arn}"
                >&4 log 0 'Failed to attach managed policy %s to role %s\n' "${policy_arn}" "$1"
                return 1
            fi
        done 3< "$2/managed_policies.txt"
    fi
}


################
# Restore inline role policies.
#
# usage: restore_inline_role_policies ROLE_NAME INLINE_POLICY_BACKUP_DIR
################
restore_inline_role_policies()
{
    local data_file
    local policy_name
    local policy_document

    # Check if inline policy backup directory exists
    if ! test -d "$2"
    then
        >&2 log 1 '*** No inline policy backup directory %s for role %s\n' "$2" "$1"
        >&4 log 0 'No inline policy backup directory %s for role %s\n' "$2" "$1"
        return 1
    fi

    # Create inline policies
    >&2 log 1 '==> Restoring inline policies\n'

    for data_file in "$2"/*.json
    do
        if test -a "${data_file}"
        then
            policy_name="${data_file##*/}"
            policy_name="${policy_name%.json}"

            # Get policy document from inline policy backup file
            if ! policy_document="$(jq --exit-status ".PolicyDocument" < "${data_file}")"
            then
                >&2 log 1 '*** No attribute PolicyDocument in backup file %s for policy %s of role %s\n' "${data_file}" "${policy_name}" "$1"
                >&4 log 0 'No attribute PolicyDocument in backup file %s for policy %s of role %s\n' "${data_file}" "${policy_name}" "$1"
                return 1
            fi

            # Create inline policy
            >&2 log 1 '==> Creating inline policy %s\n' "${policy_name}"

            if "${aws_cmd[@]}" iam put-role-policy --role-name "$1" --policy-name "${policy_name}" --policy-document "${policy_document}" --cli-input-json "$(< "${data_file}")" > /dev/null
            then
                >&4 log 0 'Created inline policy %s on role %s\n' "${policy_name}" "$1"
            else
                >&2 log 1 '*** Failed to create inline policy %s\n' "${policy_name}"
                >&4 log 0 'Failed to create inline policy %s on role %s\n' "${policy_name}" "$1"
                return 1
            fi
        fi
    done
}


################
# Restore a role.
#
# usage: restore_role ROLE_NAME ROLE_BACKUP_DIR BACKUP_ROOT
################
restore_role()
{
    local assume_role_policy_document

    if ! role_exists "$1"
    then
        # Check if role backup file exists
        if ! test -f "$2/role.json"
        then
            >&2 log 1 '*** No role backup file %s for role %s\n' "$2/role.json" "$1"
            >&4 log 0 'No role backup file %s for role %s\n\n' "$2/role.json" "$1"
            return 1
        fi

        # Get trust policy from global roles backup file
        if ! assume_role_policy_document="$(jq --exit-status --arg role_name "$1" '.[]|select(.RoleName == $role_name).AssumeRolePolicyDocument' < "$3/roles.json")"
        then
            >&2 log 1 '*** No attribute AssumeRolePolicyDocument for role %s in global roles backup file %s\n' "$1" "$3/roles.json"
            >&4 log 0 'No attribute AssumeRolePolicyDocument for role %s in global roles backup file %s\n' "$1" "$3/roles.json"
            return 1
        fi

        # Create role
        >&2 log 1 '==> Creating role %s\n' "$1"

        if "${aws_cmd[@]}" iam create-role --role-name "$1" --assume-role-policy-document "${assume_role_policy_document}" --cli-input-json "$(< "$2/role.json")" > /dev/null
        then
            >&4 log 0 'Created role %s\n' "$1"
        else
            >&2 log 1 '*** Failed to create role\n'
            >&4 log 0 'Failed to create role %s\n' "$1"
            return 1
        fi
    else
        >&2 log 1 '*** Role %s already exists - continuing\n' "$1"
        >&4 log 0 'Role %s already exists\n' "$1"
    fi
}


################
# Destroy roles read line-by-line from files.
#
# usage: destroy SOURCE_FILE ...
################
destroy()
{
    local line=""
    local line_prev=""
    local role
    local role_path

    # Set up backup directory
    if ((backups))
    then
        create_backup_dir "${backup_dir}"
        >&2 log 1 '\n'
    fi

    # Iterate over all policies
    while
        line_prev="${line}"
        read -r -u 3 line
    do
        if test -n "${line_prev}"
        then
            sleep 0.34
            >&2 echo
        fi
        >&2 log 1 '> %s\n' "${line}"

        case "${line}" in
            "")
                continue
                ;;
            arn:aws:iam::*:role/*)
                role="${line#arn:aws:iam::*:role/}"
                ;;
            arn:aws:*:*:*:*)
                >&2 log 0 '* ARN %s does not refer to an IAM role - skipping\n' "${line}"
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
                    >&2 log 0 '* Role %s is an AWS-managed role - skipping\n' "${role}"
                    continue
                fi
                ;;
        esac

        if ((${#regexps[@]})) && grep -E --line-regexp "${regexps[@]}" <<< "${role}"
        then
            >&2 log 0 '* Role %s matches an exclude-pattern - skipping\n' "${role}"
            continue
        fi
        if ! role_exists "${role}"
        then
            >&2 log 0 '* Role %s does not exist - skipping\n' "${role}"
            continue
        fi
        if ((dry_run))
        then
            >&4 log 0 'Would destroy role %s\n' "${role}"
            continue
        fi
        if ((confirm)) && ! confirm "Destroy role ${role}?"
        then
            continue
        fi

        # Create role backup directories
        if ((backups))
        then
            if ! mkdir -- "${backup_dir}/${role}"
            then
                >&2 log 0 '* Failed to create role backup directory %s\n' "${backup_dir}/$1"
                continue
            fi
            if ! mkdir -- "${backup_dir}/${role}/instance_profiles"
            then
                >&2 log 0 '* Failed to create instance profile backup directory %s\n' "${__progname__}" "${backup_dir}/instance_profiles"
                continue
            fi
            if ! mkdir -- "${backup_dir}/${role}/managed_policies"
            then
                >&2 log 0 'Failed to create managed policy backup directory%s \n' "${__progname__}" "${backup_dir}/managed_policies"
                continue
            fi
            if ! mkdir -- "${backup_dir}/${role}/inline_policies"
            then
                >&2 log 0 '* Failed to create inline policy backup directory %s\n' "${__progname__}" "${backup_dir}/inline_policies"
                continue
            fi
        fi

        # Destroy role
        >&2 log 0 'Destroying role %s\n' "${role}"
        if
            remove_role_from_instance_profiles "${role}" "${backup_dir}/${role}/instance_profiles" &&
            detach_managed_role_policies       "${role}" "${backup_dir}/${role}/managed_policies" &&
            delete_inline_role_policies        "${role}" "${backup_dir}/${role}/inline_policies" &&
            delete_role                        "${role}" "${backup_dir}/${role}"
        then
            >&2 log 0 'Success destroying role %s\n' "${role}"
        else
            >&2 log 0 'Failure destroying role %s\n' "${role}"
        fi

    done 3< <(cat -- "$@")
}


################
# Restore deleted roles from a backup directory.
#
# usage: restore SOURCE_DIRECTORY
################
restore()
{
    local backup_path
    local role=""

    # Check top-level contents of the backup directory
    check_backup_dir "$1"
    >&2 log 1 '\n'

    # Iterate over backup subdirectories (i.e. roles)
    for backup_path in "$1"/*/
    do
        backup_path="${backup_path%/}"

        if test -n "${role}"
        then
            sleep 0.34
            >&2 echo
        fi
        >&2 log 1 '> %s\n' "${backup_path}"

        role="${backup_path##*/}"

        if ((dry_run))
        then
            >&4 log 0 'Would restore role %s\n' "${role}"
            continue
        fi
        if ((confirm)) && ! confirm "Restore role ${role}?"
        then
            continue
        fi

        # Restore role
        >&2 log 0 'Restoring role %s\n' "${role}"
        if
            restore_role                  "${role}" "${backup_path}" "$1" &&
            restore_inline_role_policies  "${role}" "${backup_path}/inline_policies" &&
            restore_managed_role_policies "${role}" "${backup_path}/managed_policies" &&
            restore_instance_profiles     "${role}" "${backup_path}/instance_profiles"
        then
            >&2 log 0 'Success restoring role %s\n' "${role}"
        else
            >&2 log 0 'Failure restoring role %s\n' "${role}"
        fi
    done
}


################
# Parse options and execute role operation.
#
# usage: main ARGS ...
################
main()
{
    local aws_cmd=("aws" "--output" "json")
    local -i backups=0
    local -i confirm=0
    local -i delete_aws_roles=0
    local -i delete_instance_profiles=0
    local -i dry_run=0
    local -i verbose=0
    local regexps=()
    local profile=""
    local backup_dir=""
    local subcommand=""

    parse_opts "$@"

    shift "$((OPTIND - 1))"

    >&2 log 2 '=============================\n'
    >&2 log 2 '+ AWS CLI command:          %s\n' "${aws_cmd[*]}"
    >&2 log 2 '+ AWS CLI profile:          %s\n' "${profile}"
    >&2 log 2 '+ Backups:                  %s\n' "${backups}"
    >&2 log 2 '+ Backup directory:         %s\n' "${backup_dir}"
    >&2 log 2 '+ Confirm operations:       %s\n' "${confirm}"
    >&2 log 2 '+ Delete AWS-managed roles: %s\n' "${delete_aws_roles}"
    >&2 log 2 '+ Delete instance profiles: %s\n' "${delete_instance_profiles}"
    >&2 log 2 '+ Dry-run:                  %s\n' "${dry_run}"
    >&2 log 2 '+ Subcommand:               %s\n' "${subcommand}"
    >&2 log 2 '=============================\n\n'

    "${subcommand}" "$@"
}


main "$@"
