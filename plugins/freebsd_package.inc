# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# freebsd_package.inc 
# $Revision: 1.17 $
#

include("global_settings.inc");

# Internal use globals
global_var cvss_score, _operators_as_text;
global_var _pkg_report;
##
# String containing all affected package reporting
##
_pkg_report = '';


##
# Constants for operators as integers
##
OPERATOR_GT = 1;
OPERATOR_GTE = 2;
OPERATOR_LT = 3;
OPERATOR_LTE = 4;
OPERATOR_EQ = 5;

##
# Constants for operators back to string
##
_operators_as_text = make_array();
_operators_as_text[OPERATOR_GT]  = '>';
_operators_as_text[OPERATOR_GTE] = '>=';
_operators_as_text[OPERATOR_LT]  = '<';
_operators_as_text[OPERATOR_LTE] = '<=';
_operators_as_text[OPERATOR_EQ]  = '=';

##
# Parses name, version, and revision out of FreeBSD package
#
# @param pkg package string to parse
#
# @remark Currently, a "p" or "," in the version string will separate
#         that string into version and revision.
#
# @return my_pkg array containing key-values about package
##
function parse_pkg_name(pkg)
{
  local_var elems, i, name, version, my_pkg;

  elems = split(pkg, sep:" ", keep:0);
  elems = split(elems[0], sep:"-", keep:0);

  name = elems[0];

  for ( i = 1 ; i < max_index(elems) - 1 ; i ++ )
  {
    name += "-" + elems[i];
  }

  version = split(elems[i], sep:"_", keep:0);
  if ( version[0] == elems[i] ) version = split(elems[i], sep:"p", keep:0);
  if ( version[0] == elems[i] ) version = split(elems[i], sep:",", keep:0);
 
  my_pkg["name"]     = name;
  my_pkg["version"]  = version[0];
  my_pkg["revision"] = version[1];

  return my_pkg;
}

##
#Compares strings a and b and returns based on which
#   has an lower numeric portion or feeds into generic_str_cmp
#   if it's purely non-digit
#
# @param a version string piece
# @param b version string piece
#
# @remark Calls generic_str_cmp if no digits at front/back of both
#
# @return -1 if a starts with a digit and b doesn't ||
#              a's digits in front are < b's digits
#                in front ||
#              a's digits in back are < b's digits
#                in back ||
#              a normalized < b normalized
#          0 if a and b's digits are equal
#          1 if b starts with a digit and a doesn't ||
#              b's digits in front are < a's digits
#                in front ||
#              b's digits in back are < a's digits
#                in back ||
#              b normalized < a normalized
##
function nondigit_vers_cmp(a,b)
{
  local_var ia, ib, aa, ab, s;

  if ( a =~ "^[0-9]" && b !~ "^[0-9]" )
    return 1;
  else if ( b =~ "^[0-9]" && a !~ "^[0-9]" )
    return -1;

  if ( a =~ "^[0-9]" && b =~ "^[0-9]" )
  {
    aa = eregmatch(string:a, pattern:"^([0-9]*)(.*)$");
    ab = eregmatch(string:b, pattern:"^([0-9]*)(.*)$");
    ia = int(aa[1]);
    a = aa[2];
   
    ib = int(ab[1]);
    b = ab[2];
    s = 1;
  }
  else
  {
    aa = eregmatch(string:a, pattern:"^([^0-9]*)([0-9]*)$");
    ab = eregmatch(string:b, pattern:"^([^0-9]*)([0-9]*)$");
    ia = int(aa[2]);
    a = aa[1];
   
    ib = int(ab[2]);
    b = ab[1];
    s = 2;
    if ( a < b ) 
     return -1;
    else if ( a > b ) 
     return 1;
  }


  if ( strlen(aa[s]) && strlen(ab[s]) )
  {
    if ( ia < ib ) 
      return -1;
    else if ( ia > ib )
      return 1;
  }

  if ( strlen(a) != 0 && strlen(b) == 0 ) return 1;
  if ( strlen(b) != 0 && strlen(a) == 0 ) return -1;

  if ( a < b ) 
    return -1;
  else if ( a > b ) 
    return 1;
  else
    return 0;
}

##
#Compares version strings a and b and returns based on which
#   is lower
#
# @param a version string with . separator
# @param b version string with . separator
# @param release_diff optional difference in revision numbers
#
# @remark As it goes through different octets, it throws away the
#           largest identical parts ending in nondigits as it can
#
# @return  negative number if if an octet of a < that octet of b, digit ||
#          -1 if an octet of a < that octet of b, nondigit ||
#              a == b for all a octets but b has more
#          0 if a and b are equal
#          1 if an octet of b < that octet of a, nondigit  ||
#              a == b for all b octets but a has more ||
#            first 3 octets are identical and
#              release_diff > 0
#          positive number if if an octet of a > that octet of b, digit ||
#          NULL if the versioning has only a single octet in
#            one version but more than one in the other
##
function vers_cmp(a, b, release_diff)
{
  local_var array_a, array_b, i, max;
  local_var digit_mode_a, digit_mode_b;
 
  if ( ! a &&  b  ) return -1;
  if (  a &&  ! b  ) return 1;
  if ( ! a && ! b ) return 0;
  a = str_replace(find:"_", replace:".", string:a);
  b = str_replace(find:"_", replace:".", string:b);
  array_a = split(tolower(a), sep:".", keep:0);
  array_b = split(tolower(b), sep:".", keep:0);

  # Make sure this is the same kind of versioning
  if ( max_index(array_a) == 1 && 
    max_index(array_b) >  1 ) return NULL;

  if ( max_index(array_b) == 1 && 
    max_index(array_a) > 1 ) return NULL;

  if ( max_index(array_b) < max_index(array_a))
    max = max_index(array_a);
  else
    max = max_index(array_b);

  for ( i = 0 ; i < max ; i ++ )
  {
    # If we're past the third octet we should be at revision string
    # If a's revision string is greater here, return 1.
    if ( i > 2 && release_diff > 0 ) return 1;
    digit_mode_a = 1;
    digit_mode_b = 1;
    if ( max_index(array_a) <= i ) return -1;
    if ( max_index(array_b) <= i ) return 1;

    if ( array_a[i] !~ "^[0-9]+$" ) digit_mode_a = 0;
    if ( array_b[i] !~ "^[0-9]+$" ) digit_mode_b = 0;

    if ( digit_mode_a && digit_mode_b )
    {
      if ( int(array_a[i]) != int(array_b[i]) )
        return int(array_a[i]) - int(array_b[i]);
    }
    else if ( array_a[i] != array_b[i] )
    {
      if ( nondigit_vers_cmp(a:array_a[i], b:array_b[i]) < 0 )
        return -1;
      else 
        return  1;
    }
  }

 return 0;
}

##
# Compares the pkg and reference and returns based on which
#   is greater if applicable
#
# @param pkg complete package string from system's package list
# @param reference complete package string passed from plugin
#
#
# @return negative number if pkg and reference are for same package and
#              pkg's version < reference version or
#              pkg's revision < reference revision (if versions equal)
#         0 if pkg and reference package/version/revision are all
#              equal
#         positive number if pkg and reference are for same package and
#              pkg's version > reference version or
#              pkg's revision > reference revision (if versions equal)
#         NULL if package or reference are missing or
#              package and reference are for different packages or
#              vers_cmp returns a NULL
##
function pkg_cmp(pkg, reference)
{
  local_var my_pkg, my_reference, eq;

  if ( strlen(pkg) == 0 || strlen(reference) == 0) return NULL;
  my_pkg = parse_pkg_name(pkg:pkg);
  my_reference = parse_pkg_name(pkg:reference);

  if (my_pkg["name"] != my_reference["name"]) return NULL;
  eq = vers_cmp(a:my_pkg["version"], b:my_reference["version"], release_diff:vers_cmp(a:my_pkg["revision"], b:my_reference["revision"]));
  if ( isnull(eq) ) return NULL;
  if ( eq ) return eq;
	
 
  if ( !isnull(my_reference["revision"]) &&
    isnull(my_pkg["revision"])  ) return -1;


  eq = vers_cmp(a:my_pkg["revision"], b:my_reference["revision"]);
  return eq; 
}

##
# Finds appropriate operator constant based on operator
#
# @param str complete package string from system's package list
#
# @return -1 if no meaningful identifier for str's operator exists
#          0 if str is empty
#          appropriate operator constant based on first two characters
#            in str
##
function pkg_op(str)
{
  if ( isnull(str) || strlen(str) == 0 ) return 0;
  if ( str[0] == ">" && strlen(str) > 1 && str[1] == "=" ) return OPERATOR_GTE; 
  else if ( str[0] == ">" ) return OPERATOR_GT; 
  else if ( str[0] == "=" ) return OPERATOR_EQ; 
  else if ( str[0] == "<" && strlen(str) > 1 && str[1] == "=") return OPERATOR_LTE;
  else if ( str[0] == "<" ) return OPERATOR_LT;
  else return -1;
}

##
# Determines if a package is affected based on the operator and
# the result of a pkg_cmp() called passed to n
#
# @param op integer representing an operator constant code
# @param n integer representing results of a pkg_cmp() call
#
# @return 1 if the n result of pkg_cmp() represents a situation where
#           the op operator is accurate
#         0 otherwise
##
function pkg_op_match(op, n)
{
 if ( (op == OPERATOR_GT || op == OPERATOR_GTE) && n > 0 ) return 1;
 if ( (op == OPERATOR_LT || op == OPERATOR_LTE) && n < 0 ) return 1;
 if ( (op == OPERATOR_EQ || op == OPERATOR_LTE || op == OPERATOR_GTE ) && n == 0 ) return 1;
 return 0;
}

##
# Determines if a specific pkg has an install in Host/FreeBSD/pkg_info
# that is affected by a vulnerability, based on the operator criteria
# included in the pkg line
#
# @param pkg package name, operator, and version determining what is
#          vulnerable
# @param save_report boolean argument for whether or not to store the
#          affected packages report, or to run security functions
#          immediately (for legacy plugins)
#
# @return -1 if pkg is affected
#          0 if no appropriate operator is found ||
#               pkg_name is FreeBSD but Host/FreeBSD/release cannot be
#                 found ||
#               pkg_name is not FreeBSD but it is not found in
#                 pkg_info ||
##
function pkg_test(pkg, save_report)
{
  local_var affected_version, pkg_name, orig, op1, op2, op1_arg;
  local_var op2_arg, n, pkgs, package, report, installed_version;

  pkgs = get_kb_item("Host/FreeBSD/pkg_info");
 
  orig = pkg;

  pkg_name = ereg_replace(pattern:"([^<>=]*).*", string:pkg, replace:"\1");
  pkg -= pkg_name;

  # Required for compatibility with legacy FreeBSD plugins
  if ( isnull(pkgs) || !strlen(pkgs) && pkg_name != "FreeBSD") exit(0, 'Empty list of FreeBSD packages.');

  pkg_name = str_replace(find:"{", replace:"(", string:pkg_name);
  pkg_name = str_replace(find:"}", replace:")", string:pkg_name);
  pkg_name = str_replace(find:",", replace:"|", string:pkg_name);

  # Because of the regexes here a return value of -1 is unlikely
  op1 = pkg_op(str:pkg);
  if (op1 < 1 )
  {
    return 0;
  }
  else if ( op1 > 0 ) op1_arg = ereg_replace(pattern:"^[<>=]*([^<>=]*).*", string:pkg, replace:"\1");

  pkg = ereg_replace(pattern:"^[<>=]*([^<>=]*)(.*)", string:pkg, replace:"\2");
  op2 = pkg_op(str:pkg);
  if (op2 < 0 )
  {
    return 0;
  } else if ( op2 > 0 ) op2_arg = ereg_replace(pattern:"^[<>=]*([^<>=]*).*", string:pkg, replace:"\1");

  if (pkg_name == "FreeBSD")
  {
    package = get_kb_item("Host/FreeBSD/release");
    # This shouldn't ever happen.
    if (!package) return 0;
  }
  else
  {
    package = egrep(pattern:"^" + pkg_name + "-", string:pkgs);
    if (!package) return 0;
  }

  n = pkg_cmp(pkg:package, reference:pkg_name + "-" + op1_arg);
  if (isnull(n)) return 0;    # name parts don't match!
  if (!pkg_op_match(op:op1, n:n)) return 0;

  # We do not flag checks that say all versions > X vulnerable.
  if ( op2 == 0 && ( op1 == OPERATOR_GT || op1 == OPERATOR_GTE ) ) return 0;


  if ( op2 != 0 )
  {
    n = pkg_cmp(pkg:package, reference:pkg_name + "-" + op2_arg);
    if ( !pkg_op_match(op:op2, n:n) ) return 0;
  }

  if (save_report)
  {
    installed_version = ereg_replace(pattern:"^([^ ]*).*", string:package,replace:"\1") - pkg_name - '-';
    affected_version = _operators_as_text[op1] + " " + op1_arg + " " + 
                       _operators_as_text[op2] + " " + op2_arg;
    if (pkg_name == "FreeBSD")
    {
      _pkg_report += '  - Installed release   : ' + installed_version + '\n' +
                     '    Affected release(s) : ' + affected_version + '\n' +
                     '\n';
    }
    else
    {
      _pkg_report += '  - Package             : ' + pkg_name + '\n' +
                     '    Installed version   : ' + installed_version + '\n' +
                     '    Affected version(s) : ' + affected_version + '\n' +
                     '\n';
    }
  }
  else
  {
    if (pkg_name == "FreeBSD")
    {
      report = 'The remote OS is not up-to-date.\n';
      report += ' - ' + ereg_replace(pattern:"^([^ ]*).*", string:package,replace:"\1") + ' is installed on the remote host.\n';
    }
    else
    {
      report = "The remote package " + ereg_replace(pattern:"^([^ ]*).*", string:package,replace:"\1") + ' is not up-to-date.\n';
      report += ' - ' + package + ' is installed on the remote host.\n';
    }

    if ( isnull(cvss_score) ) cvss_score = 10;
    if ( cvss_score >= 7 )
      security_hole(port:0, extra:report);
    else if ( cvss_score >= 4 )
      security_warning(port:0, extra:report);
    else
      security_note(port:0, extra:report);
  }

  return 1;
}

##
# Returns _pkg_report string if it exists
#
# @return _pkg_report preceded by a newline with trailing newlines
#           removed if it exists and has a length
#         NULL otherwise
##
function pkg_report_get()
{
  if (strlen(_pkg_report)) return '\n' + chomp(_pkg_report);
  else return NULL;
}
