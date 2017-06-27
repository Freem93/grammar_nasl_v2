#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# readykernel.inc
# $Revision: 1.2 $
#

include("audit.inc");
include("misc_func.inc");
include("rpm.inc");

# The comparison return array object
# {
#   isError : TRUE/FALSE
#   isSuccess : TRUE/FALSE
#   ver : ""
#   fix : ""
#   comparisonResult : "equal" or "greater" or "lesser"
#   error : ""
# }

##
# Checks values of readykernel data to determine if version at target
# meets the comparison criteria for the fixed version of the
# readykernel patch level
#
# @param fix Version to compare the readykernel
#              rpm-list KB entries
# @param criteria list of valid OR'd criteria for fix and
#              the installed version's relationship
#
# @return TRUE if no errors occur and the comparisonResult matches
#              any one of the criteria
#         FALSE otherwise
##
function readykernel_check(fix, criteria) {
  local_var readykernel_data, criterion;
  readykernel_data = _init_readykernel_check(fix:fix);
  if ( readykernel_data['isError'] ) return FALSE;
  _populate_readykernel_version(check:readykernel_data);
  if ( readykernel_data['isError'] ) return FALSE;
  if ( isnull(criteria) || len(criteria) < 1 ) return FALSE;
  _perform_readykernel_check(check:readykernel_data);
  if ( readykernel_data['isSuccess'] && readykernel_data['comparisonResult']) {
    foreach criterion (criteria) {
      if (readykernel_data['comparisonResult'] == criterion )  return TRUE;
    }
  }
  # No criteria were met
  return FALSE;
}


##
# Calls readykernel_check with "lesser" as the criteria
#
# @param fix Version to compare the readykernel
#              rpm-list KB entries
#
# @return Value given to it by the readykernel_check() call
##
function readykernel_check_lesser_and_valid(fix) {
  return readykernel_check(fix:fix, criteria:make_list("lesser"));
}

##
# Calls readykernel_check with "lesser", "equal" as the criteria
#
# @param fix Version to compare the readykernel
#              rpm-list KB entries
#
# @return Value given to it by the readykernel_check() call
##
function readykernel_check_lesser_equal_and_valid(fix) {
  return readykernel_check(fix:fix, criteria:make_list("lesser","equal"));
}

##
# Calls readykernel_check with "greater" as the criteria
#
# @param fix Version to compare the readykernel
#              rpm-list KB entries
#
# @return Value given to it by the readykernel_check() call
##
function readykernel_check_greater_and_valid(fix) {
  return readykernel_check(fix:fix, criteria:make_list("greater"));
}

##
# Calls readykernel_check with "greater", "equal" as the criteria
#
# @param fix Version to compare the readykernel
#              rpm-list KB entries
#
# @return Value given to it by the readykernel_check() call
##
function readykernel_check_greater_equal_and_valid(fix) {
  return readykernel_check(fix:fix, criteria:make_list("greater","equal"));
}

##
# Calls readykernel_check with "equal" as the criteria
#
# @param fix Version to compare the readykernel
#              rpm-list KB entries
#
# @return Value given to it by the readykernel_check() call
##
function readykernel_check_equal_and_valid(fix) {
  return readykernel_check(fix:fix, criteria:make_list("equal"));
}

##
# Populates the fixed version of readykernel into the check array, or
# sets error information if it's missing.
#
# @param fix Fix version to populate the readykernel
#              comparison array with
#
# @return Does not return, modifies check array
##
function _init_readykernel_check(fix) {
  local_var readykernel_data;
  if ( empty_or_null(fix) ) {
    readykernel_data['isError'] = TRUE;
    readykernel_data['error'] = "fix is missing or empty in readykernel_check functions";
  } else {
    readykernel_data['fix'] = chomp(fix);
  }
  return readykernel_data;
}

##
# Populates the patch version of readykernel into the check array
#
# @param check Array reference to put results into
#
# @return Does not return, modifies check array
##
function _populate_readykernel_version(&check) {
  local_var ver;
  ver = _fetch_readykernel_version();
  check['ver'] = ver;
}

##
# Fetches the installed patch of readykernel or returns
# "readykernel-patch-0" as the patch version.
#
# @return "readykernel-patch-0" if Host/readykernel-patch-level is empty or null
#           else returns value of Host/readykernel-patch-level
##
function _fetch_readykernel_version() {
  local_var ver;
  ver = get_kb_item("Host/readykernel-patch-level");
  if ( empty_or_null(ver) ) {
    # This is valid, not having a readykernel patch installed. Simply set it to readykernel-patch-0.
    return "readykernel-patch-0";
  } else {
    return chomp(ver);
  }
}

##
# Splits readykernel-patch versions by dashes and then ver_compares
#   each part individually
#
# @param ver version (with dashes) of readykernel-patch on system
#
# @param fix version (with dashes) of readykernel-patch required
#
# @return 0 if ver and fix are equivalent or
#         1 if ver > fix or ver has more dashed sections and is
#           equivalent through fix's length or
#         -1 if ver < fix or fix has more dashed sections and is
#           equivalent through ver's length or
#         NULL if either fix or ver are empty_or_null() or contain alphas
##
function _split_dashes_and_compare(fix, ver) {
  local_var flen, vlen, ffield, vfield, ver_compare_result, i;
  local_var regex;
  if ( empty_or_null(ver) ) {
    return NULL;
  }
  if ( empty_or_null(fix) ) {
    return NULL;
  }
  # If any non-numeric portions of the version string remain, we
  # have not properly handled the input, so scream and die.
  regex = "^[-\d]+(\.[-\d]+)*$";
  if (ver !~ regex || fix !~ regex)
  {
    return NULL;
  }
  ver = split(ver, sep:'-', keep:FALSE);
  fix = split(fix, sep:'-', keep:FALSE);
  vlen = max_index(ver);
  flen = max_index(fix);
  for (i = 0; i < vlen && i < flen; i++)
  {
    vfield = ver[i];
    ffield = fix[i];
    ver_compare_result = ver_compare(fix:ffield, ver:vfield, strict:FALSE);
    if (ver_compare_result > 0 || ver_compare_result < 0)
      return ver_compare_result;
  }
  # If we're here, we ran out of fields in one or both versions
  if (flen > vlen)
    return -1;
  if (vlen > flen)
    return 1;
  # If the length is the same, they're equal.
  return 0;
}

##
# Executes the check to determine if ver is lesser/greater/equal
# and sets the appropriate result in the check array,
# or sets error information if ver and fix are missing or badly
# formatted.
#
# @param check Array reference to put results into
#
# @return Does not return, modifies check array
##
function _perform_readykernel_check(&check) {
  local_var ver, fix, ver_compare_result, readykernel_patch_pattern;
  local_var ver_patch_level, fix_patch_level;
  # Error check first
  if ( empty_or_null(check['ver']) ) {
    check['isError'] = TRUE;
    check['error'] = "ver is missing or empty in _perform_readykernel_check function";
  } else if ( empty_or_null(check['fix']) ) {
    check['isError'] = TRUE;
    check['error'] = "fix is missing or empty in _perform_readykernel_check function";
  } else {
    # Ensure both begin with readykernel-patch
    # Also trim out the readykernel-patch- at the start and .vl# at the end
    readykernel_patch_pattern = "^readykernel-patch-(.+?)(\.vl[0-9])?$";
    ver_patch_level = pregmatch(string: check['ver'], pattern: readykernel_patch_pattern);
    if ( isnull(ver_patch_level) || empty_or_null(ver_patch_level[1]) ) {
      check['isError'] = TRUE;
      check['error'] = "ver is not a valid readykernel-patch- value";
    } else {
      ver = ver_patch_level[1];
      fix_patch_level = pregmatch(string: check['fix'], pattern: readykernel_patch_pattern);
      if ( isnull(fix_patch_level) || empty_or_null(fix_patch_level[1]) ) {
        check['isError'] = TRUE;
        check['error'] = "fix is not a valid readykernel-patch- value";
      } else {
        fix = fix_patch_level[1];
        # Do the actual comparison of ver and fix now.
        ver_compare_result = _split_dashes_and_compare(fix:fix, ver:ver); 
        if (isnull(ver_compare_result) ) {
          # The null conditions for ver_compare are all errors.
          # Check NULL first because it truthies with 0.
          check['isError'] = TRUE;
          check['error'] = "ver_compare for ver and fix returned NULL";
        } else if (ver_compare_result == 0) {
          check['comparisonResult'] = "equal";
          check['isSuccess'] = TRUE;
        } else if (ver_compare_result == -1) {
          check['comparisonResult'] = "lesser";
          check['isSuccess'] = TRUE;
        } else if (ver_compare_result == 1) {
          check['comparisonResult'] = "greater";
          check['isSuccess'] = TRUE;
        }
      }
    }
  }
}

# Example
#checks = make_list(
#  make_array(
#    "kernel":"vzkernel-3.10.0-327.18.2.vz7.15.2",
#    "patch":"readykernel-patch-15.2-10.0-1.vl7"
#  ),
#  make_array(
#    "kernel":"vzkernel-3.10.0-327.36.1.vz7.18.7",
#    "patch":"readykernel-patch-18.7-10.0-1.vl7"
#  ),
#  make_array(
#    "kernel":"vzkernel-3.10.0-327.36.1.vz7.20.18",
#    "patch":"readykernel-patch-20.18-10.0-1.vl7"
#  )
#);
#readykernel_execute_checks(checks:checks, severity:SECURITY_WARNING, release:"Virtuozzo-7");

##
# Loops through passed in readykernel checks and checks for
# equal kernel levels, running the appropriate
# ready_kernel_check_lesser_and_valid check, and auditing/reporting
# appropriately.
#
# @param checks list of arrays containing the readykernel kernel and
#              patch information
# @param severity severity of reporting to pass to security_report_v4
# @param release Version of rpm operating system to check against
# @param use_returns Flag to indicate being run in a unit test setup,
#              suppresses audits and reports, returns instead
#
# @return Only returns in unit test mode or argument error
#              returns appropriate error string or report
#         else audits or security_reports and exits
##
function readykernel_execute_checks(checks, severity, release, use_returns) {
# Foreach check
#   rpm_exist the kernel, ensure !isnull and == 0. 
#     readykernel_check_equal_and_valid the fix
#     report and exit or
#     audit not applicable
# If none of checks applied, audit.
  local_var check, kernel_audit_list, kernel, patch;
  local_var kernel_check_result, readykernel_result;
  local_var readykernel_report;
  if (empty_or_null(checks) || empty_or_null(severity) || empty_or_null(release) ) {
    return "Empty or null arguments provided.";
  }
  foreach check (checks) {
    if (empty_or_null(check['kernel']) ) {
      return "Empty or null kernel argument for one of the checks";
    } else {
      kernel = check['kernel'];
    }
    if (empty_or_null(check['patch']) ) {
      return "Empty or null patch argument for one of the checks";
    } else {
      patch = check['patch'];
    }
    if ( empty_or_null(kernel_audit_list) ) {
      kernel_audit_list = kernel;
    } else {
      kernel_audit_list += ' / ' + kernel;
    }
    # Check to see if the kernel is installed
    kernel_check_result = rpm_exists(release:release, rpm:kernel);
    if ( !empty_or_null(kernel_check_result) && kernel_check_result == 1 ) {
      readykernel_result = readykernel_check_lesser_and_valid(fix:patch);
      if (readykernel_result) {
        # Make report text
        readykernel_report = 'Readykernel patch installed : ' + _fetch_readykernel_version() + '\n' +
		             'Should be                   : ' + patch + '\n\n';
        # Replace the default of readykernel-patch-0 with None
        readykernel_report = ereg_replace(string:readykernel_report, pattern:"readykernel-patch-0([^0-9\.])", replace:"None\1");
        # Report
        if (use_returns) return readykernel_report;
        security_report_v4(
          port       : 0,
          severity   : severity,
          extra      : readykernel_report
        );
        exit(0);
      } else {
        if (use_returns) return "AUDIT: Package not affected (" + kernel + ")";
        audit(AUDIT_PACKAGE_NOT_AFFECTED, kernel);
      }
    }
  }
  # None of the checks applied
  if (use_returns) return "AUDIT: Package not installed (" + kernel_audit_list + ")";
  audit(AUDIT_PACKAGE_NOT_INSTALLED, kernel_audit_list);
  # Catch-all return, we should have audited or exited by now.
  return "End of readykernel_execute_checks";
}

