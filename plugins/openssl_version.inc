#TRUSTED 914ff0b5ad32d8c0e19e61e31da9883c3928c97f278ffd1d6660a74501aa0df33c9ad245ab4d4a9bc19d67679aa18984fddd2b4771756cf47bf6df4fbc7495928042237719166ad99d5b643934f435dddaa4014f816ebcf7abe558f65306fd51f35d4dde0b846ecb32e96c6f64fcba62c188bd7d77804c77dc5fb40e27d26eb411070644378b4d2dadfacd63091cded6e87309035e4c4365c319530d6314b84a584eec36b494e6eee7c265c1ef7437f042794655b08e50d45416dee9ec81eea3ab5db6b6275283de4ea73ae6e602640c73e56f2c1bc41da501f5eeffc28d5dfa9ea4fd16216da6f6705f4c4cd06afe15c90715498603e2f1dbd7e66eaf35bffb7b92afde18daa8c2c1df85d246ac4285b65ee631c3c2474f53b18b00e429bfed17c9c0faa4a9a5aa4e4a08e7ac74af6a6a5ccf96ab077cc2525caa393800033d9086848ee21cd546cfd45de2a0d41d8e9dc5a5802ee7d77f9815eacbab5b4fcbb591335e8c045e0e09646fc00768328bf2842dc1f0d4bab9308e63ace3ea9ccc18a0c287256c550eb9d15970a5ab4aee0e2ee42b4194619d8e062af5f66168d6956f203ce159245f8f09db282e4a7e719e885ce66026f4595fd3ad346cd2eab69c71c2e450323497b0026c9269c5a0ec61b929e7798987bcd77e921cb4e0d9ceee4247c3c1f6bacda58e2bcb28f0d9c58611c0f99df197ca62d833003cc69701
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "OpenSSL";

# compares two OpenSSL versions. each version must be all numeric and
# can end with a letter, optionally with a beta version number
# e.g. 0.9.6e
# or   1.0.0-beta1
#
# Additional text like -fips, -pre, or -rhel5 is erased & ignored currently.
#
# args: ver, fix - versions to compare
#
# returns -1	if ver < fix
#          0	if ver == fix
#          1	if ver > fix
#	   NULL	error, invalid format
#
function openssl_ver_cmp(ver, fix, same_branch, is_min_check)
{
  local_var	pat, vv, ff, i, v, f;

  # Do not anchor on the right, version might be "0.9.8e-fips-rhel5"
  pat = '^([0-9]+)\\.([0-9]+)\\.([0-9]+)([a-z]+)?((-fips)?(-beta([0-9]+))?(-pre([0-9]+))?)?';

  vv = eregmatch(string: ver, pattern: pat, icase: FALSE);
  if (isnull(vv))
  {
    err_print('openssl_ver_cmp: invalid version ver=', ver);
    return NULL;
  }

  ff = eregmatch(string: fix, pattern: pat, icase: FALSE);
  if (isnull(ff))
  {
    err_print('openssl_ver_cmp: invalid version fix=', fix);
    return NULL;
  }

  for (i = 1; i <= 3; i ++)
  {
    v = int(vv[i]);
    f = int(ff[i]);
    if (same_branch)
    {
      if (v != f) return 0;
    }
    else
    {
      if (v < f) return -1;
      if (v > f) return 1;
    }
  }

  # a < z is safe
  # z < za is safe
  # za < zz is safe
  v = vv[4];
  f = ff[4];
  if (v < f) return -1;
  if (v > f) return 1;

  # handles match 8 for -beta, and match 10 for -pre
  if ((! isnull(vv[8]) || ! isnull(ff[8])) || (! isnull(vv[10]) || ! isnull(ff[10])))
  {
    if ((! isnull(vv[8]) || ! isnull(ff[8])))
    {
      v = int(vv[8]);
      f = int(ff[8]);
    }
    else
    {
      v = int(vv[10]);
      f = int(ff[10]);
    }

    if (v != f)
    {
      # No beta or pre is newer than betaXXX or preXXX

      # In a min_check, betas/pres are not vuln
      if (is_min_check)
      {
        if (v == 0) return -1;
        if (f == 0) return 1;
      }
      else
      {
        # In a normal check, betas/pres are vuln
        if (v == 0) return 1;
        if (f == 0) return -1;
      }

      if (v < f) return -1;
      if (v > f) return 1;
    }
  }
  return 0;
}

####

global_var	port, ver;

##
# Checks if server's OpenSSL version is vulnerable.
#
# @param  list   fixed list of fixed versions
# @param  int    severity reporting severity
# @param  string min minimum vulnerable version
#
# @remark This function does not return, it either reports or exits.
##
function openssl_check_version(fixed, severity, min)
{
  local_var port;
  local_var kb_base;
  local_var banner, version, backported;
  local_var fix, same_branch;
  local_var report;

  report = '';

  # Make sure OpenSSL is installed.
  port = get_kb_item("openssl/port");
  if (isnull(port)) audit(AUDIT_NOT_INST, app_name);

  # Get relevant data for installed version.
  kb_base = "openssl/" + port + "/";
  banner = get_kb_item(kb_base + "pristine_banner");
  version = get_kb_item(kb_base + "pristine_version");
  backported = get_kb_item(kb_base + "backported");

  # If the banner is backported, and we're not running a paranoid
  # scan, audit out.
  if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, app_name);

  # Make sure the version is above the min vuln version.
  if (!isnull(min) && openssl_ver_cmp(ver:version, fix:min, same_branch:FALSE, is_min_check:TRUE) < 0)
    audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

  # Check against list of fixes.
  fixed = make_list(fixed);
  if (len(fixed) > 1) same_branch = TRUE;
  else same_branch = FALSE;

  foreach fix (fixed)
  {
    if (openssl_ver_cmp(ver:version, fix:fix, same_branch:same_branch) < 0)
    {
      report =
        '\n  Banner           : ' + banner +
        '\n  Reported version : ' + version +
        '\n  Fixed version    : ' + fix;

      if (backported) report +=
        '\n\nBased on the banner, security patches may have been backported to' +
        '\nthis install of OpenSSL. A local check is needed to confirm the' +
        '\npresence of this vulnerability.';

      report += '\n';
      security_report_v4(port:port, severity:severity, extra:report);
      exit(0);
    }
  }

  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
}

# Local Variables:
# mode:Fundamental
# End:
