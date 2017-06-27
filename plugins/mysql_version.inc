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
# mysql_version.inc
# $Revision: 1.14 $
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");
include("rpm.inc");

##
# Default list for RPM checks for RHEL-type OS levels
##
default_mysql_rhel_os_list = make_list(
  "EL5",
  "EL6",
  "EL7",
  "FC20",
  "FC21",
  "FC22",
  "FC23",
  "RHEL5",
  "RHEL6",
  "RHEL7",
  "SL5",
  "SL6",
  "SL7"
);

##
# Default list for RPM checks for Amazon Linux OS
##
default_mysql_ala_os_list = make_list(
  "ALA"
);

##
# Default list for RPM checks for SUSE-type OS levels
##
default_mysql_suse_os_list = make_list(
  "SLED11",
  "SLED12",
  "SLES11",
  "SLES12",
  "SUSE13.1",
  "SUSE13.2",
  "SUSE42.1"
);

##
# Default list for RPM checks for CentOS OS levels
##
default_mysql_centos_os_list = make_list(
  "CentOS-5",
  "CentOS-6",
  "CentOS-7"
);

##
# Default list for all MySQL RPM packages
##
default_mysql_rpm_list_all = make_list(
  "mysql-community-client",
  "mysql-community-common",
  "mysql-community-devel",
  "mysql-community-embedded",
  "mysql-community-libs",
  "mysql-community-libs-compat",
  "mysql-community-server",
  "MySQL-client",
  "MySQL-client-advanced",
  "MySQL-devel",
  "MySQL-devel-advanced",
  "MySQL-shared",
  "MySQL-shared-advanced",
  "MySQL-shared-compat",
  "MySQL-shared-compat-advanced",
  "MySQL-server",
  "MySQL-server-advanced"
);

##
# Default list for client MySQL RPM packages
##
default_mysql_rpm_list_client_only = make_list(
  "mysql-community-client",
  "MySQL-client",
  "MySQL-client-advanced"
);

##
# Default list for server MySQL RPM packages
##
default_mysql_rpm_list_server_only = make_list(
  "mysql-community-common",
  "mysql-community-devel",
  "mysql-community-embedded",
  "mysql-community-libs",
  "mysql-community-libs-compat",
  "mysql-community-server",
  "MySQL-devel",
  "MySQL-devel-advanced",
  "MySQL-shared",
  "MySQL-shared-advanced",
  "MySQL-shared-compat",
  "MySQL-shared-compat-advanced",
  "MySQL-server",
  "MySQL-server-advanced"
);

##
# Compares passed Oracle MySQL rpm packages against specific versions for
#   any affected rpm-lists on the target system
#
# @param mysql_packages List of packages to check against
# @param fix_ver version of Oracle MySQL to check against
# @param exists_ver minimum version piece of Oracle MySQL version to do an
#          rpm_exists check against
# @param rhel_os_list list of RedHat family OS releases to check against
# @param centos_os_list list of CentOS OS releases to check against
# @param suse_os_list list of SUSE OS releases to check against
# @param ala_os_list list of AmazonLinux OS releases to check against
# @param severity Nessus severity level to report at
#
# @return Does not return, reports if packages affected.
##
function mysql_check_rpms(mysql_packages, fix_ver, exists_ver, rhel_os_list, centos_os_list, suse_os_list, ala_os_list, severity)
{
  local_var os_list, os_rel, package_name, check_package, exists_package, report_extra, flag, tested;
  local_var rhel_release, ala_release, suse_release, centos_release;

  if (empty_or_null(fix_ver)) exit(1, "Missing 'fix_ver' value in mysql_check_rpms");
  if (empty_or_null(exists_ver)) exit(1, "Missing 'exists_ver' value in mysql_check_rpms");
  if (empty_or_null(mysql_packages)) exit(1, "Missing 'mysql_packages' value in mysql_check_rpms");
  if (empty_or_null(severity)) exit(1, "Missing 'severity' value in mysql_check_rpms");

  if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

  rhel_release = get_kb_item("Host/RedHat/release");
  ala_release = get_kb_item("Host/AmazonLinux/release");
  suse_release = get_kb_item("Host/SuSE/release");
  centos_release = get_kb_item("Host/CentOS/release");
  if (!rhel_release && !ala_release && !suse_release && !centos_release) audit(AUDIT_OS_NOT, "affected");

  if (!get_kb_item("Host/RedHat/rpm-list")
   && !get_kb_item("Host/AmazonLinux/rpm-list")
   && !get_kb_item("Host/SuSE/rpm-list")
   && !get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

  os_list = make_list();

  if (!empty_or_null(rhel_os_list) && !empty_or_null(rhel_release) && get_kb_item("Host/RedHat/rpm-list")) os_list = make_list(os_list, rhel_os_list);
  if (!empty_or_null(ala_os_list) && !empty_or_null(ala_release) && get_kb_item("Host/AmazonLinux/rpm-list")) os_list = make_list(os_list, ala_os_list);
  if (!empty_or_null(suse_os_list) && !empty_or_null(suse_release) && get_kb_item("Host/SuSE/rpm-list")) os_list = make_list(os_list, suse_os_list);
  if (!empty_or_null(centos_os_list) && !empty_or_null(centos_release) && get_kb_item("Host/CentOS/rpm-list")) os_list = make_list(os_list, centos_os_list);
  if (empty_or_null(os_list)) audit(AUDIT_OS_NOT, "affected");

  flag = 0;

  foreach os_rel (os_list)
  {
    foreach package_name (mysql_packages)
    {
      check_package = package_name + "-" + fix_ver + "-0";
      exists_package = package_name + "-" + exists_ver;
      if (rpm_exists(release:os_rel, rpm:exists_package) && rpm_check(release:os_rel, reference:check_package)) flag++;
    }
  }

  if (flag)
  {
    report_extra = rpm_report_get();
    report_extra = ereg_replace(pattern:"\n(Should be *: .+?)-0\n", replace:'\n\\1\n', string:report_extra);
    security_report_v4(port:0, extra:report_extra, severity:severity);
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Oracle MySQL " + exists_ver);
  }
}

##
# Compares two MySQL versions
#
# @param ver version string with . separator
# @param fix version string with . separator
#
# @return -1 if ver < fix
#         0 if ver == fix
#         1 if ver > fix
#         NULL if format of ver or fix are invalid, or there's an error 
##
function mysql_ver_cmp(ver, fix, same_branch)
{
  local_var pat, vv, ff, i, v, f, n;

  pat = '^(([0-9]+)\\.)+([0-9]+)';

  vv = eregmatch(string: ver, pattern: pat, icase: FALSE);
  if (isnull(vv))
  {
    err_print('mysql_ver_cmp: invalid version ver=', ver);
    return NULL;
  }

  ff = eregmatch(string: fix, pattern: pat, icase: FALSE);
  if (isnull(ff))
  {
    err_print('mysql_ver_cmp: invalid version fix=', fix);
    return NULL;
  }

  vv = split(ver, sep: '.', keep: 0);
  ff = split(fix, sep: '.', keep: 0);
  n = max_index(vv); if (max_index(ff) > n) n = max_index(ff);

  if (same_branch)
  {
    v = int(vv[0]);
    f = int(ff[0]);
    if (v != f) return 0;
    if (v >= 4)
    {
      v = int(vv[1]);
      f = int(ff[1]);
      if (v != f) return 0;
    }
  }

  for (i = 0; i < n; i ++)
  {
    v = int(vv[i]); f = int(ff[i]);
    if (v < f) return -1;
    if (v > f) return 1;
  }

  return 0;
}

##
# Checks version of MySQL/MariaDB on remote system for being less than
#   fixed versions and reports if so, or exits.
#
# @param fixed list of fixed MySQL versions to check for being lower than
# @param fixed_string String to replace actual fixed version with in reporting
# @param severity Nessus severity level to report at
# @param min minimum version level of potentially affected versions
# @param variant specific MySQL or MariaDB variant to check against
# @param paranoid flag for setting check as report_paranoia > 2 only
# @param sslvuln flag that if true specifies the remote server must support
#        ssl connections to be vulnerable
#
# @remark WARNING! This function may fork, and never returns, only exits.
#
# @return Never
##
function mysql_check_version(fixed, fixed_string, severity, min, variant, paranoid, sslvuln)
{
  local_var match, report, br, f, port, real_ver, ver, ver_ui, sqlvar;

  # Banner checks of open source software are prone to false-
  # positives so only run the check if reporting is paranoid.
  if (! paranoid && report_paranoia < 2)
    exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

  port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);
  mysql_init(port: port, exit_on_fail: TRUE);
  ver = mysql_get_version();
  # if (isnull(ver) ver = get_mysql_version(port: port);
  if (isnull(ver)) exit(1, 'Failed to get the version from the server listening on port '+port+'.');

  sqlvar = mysql_get_variant();

  if (sslvuln && !mysql_supports_ssl())
    exit(0, 'The remote MySQL server listening on port '+port+' does not support SSL connections.');

  if (variant != '' && !isnull(variant))
  {
    if (isnull(sqlvar)) exit(1, "Failed to determine the MySQL variant listening on port "+port+".");
    if (variant >!< sqlvar)
      exit(0, 'The MySQL server listening on port '+port+' does not run the right variant.');
  }
  else
  {
    # If variant is not specified in call, but remote
    # install is the variant, do not attempt check.
    if ("MariaDB" >< sqlvar)
      exit(0, "The server listening on port " + port + " is MariaDB, but this variant was not specified to be checked.");
    else if ("Cluster" >< sqlvar)
      exit(0, "The server listening on port " + port + " is MySQL Cluster, but this variant was not specified to be checked.");
  }

  # Fix up variant version.
  real_ver = ver;
  if ("MariaDB" >< sqlvar)
  {
    match = eregmatch(pattern:"^5\.5\.5-([0-9]+\.[0-9]+\.[0-9]+)-MariaDB", string:ver);
    if (!isnull(match)) ver = match[1];
  }
  else if ("Cluster" >< sqlvar)
  {
    match = eregmatch(pattern:"^\d+\.\d+\.\d+-ndb-(\d+\.\d+\.\d+)-cluster", string:ver);
    if (!isnull(match)) ver = match[1];
  }

  if (! isnull(min))
    if (mysql_ver_cmp(ver: ver, fix: min, same_branch: 0) < 0)
    {
      if ("MariaDB" >< sqlvar) exit(0, "The MariaDB "+ver+" server listening on port " + port + " is not affected.");
      else if ("Cluster" >< sqlvar) exit(0, "The MySQL Cluster "+ver+" server listening on port " + port + " is not affected.");
      else exit(0, "The MySQL "+ver+" server listening on port " + port + " is not affected.");
    }

  fixed = make_list(fixed);
  br = (max_index(fixed) > 1);

  foreach f (fixed)
  {
    if (mysql_ver_cmp(ver: ver, fix: f, same_branch: br) < 0)
    {
      report = NULL;
      if (report_verbosity > 0)
      {
        report = "";
        ver_ui = ver;
        if (ver != real_ver) ver_ui += " (" + real_ver + ")";

        if (variant != '') report += '\n  Variant           : ' + sqlvar;

        # Allow the fix to be overridden if it has not been published
        if (fixed_string) f = fixed_string;

        report += '\n  Installed version : ' + ver_ui +
                  '\n  Fixed version     : ' + f + '\n';
      }

      security_report_v4(port: port, extra: report, severity: severity);
      exit(0);
    }
  }
  if ("MariaDB" >< sqlvar) exit(0, "The MariaDB "+ver+" server listening on port " + port + " is not affected.");
  else if ("Cluster" >< sqlvar) exit(0, "The MySQL Cluster "+ver+" server listening on port " + port + " is not affected.");
  else exit(0, "The MySQL "+ver+" server listening on port " + port + " is not affected.");
}
