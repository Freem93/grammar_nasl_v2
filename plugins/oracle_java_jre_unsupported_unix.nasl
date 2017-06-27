#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64816);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/07 22:01:24 $");

  script_name(english:"Oracle Java JRE Unsupported Version Detection (Unix)");
  script_summary(english:"Checks if any Oracle Java JRE installations are unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more unsupported versions of the
Oracle Java JRE.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, at least one
installation of Oracle (formerly Sun) Java JRE on the remote host
is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that Oracle does provide support contracts under the 'Oracle
Lifetime Support' program. If the detected JRE is supported under this
program, this may be a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/us/support/lifetime-support-068561.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Oracle Java JRE that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("Host/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

#
# Execution begins here
#

jre_installs = get_kb_list("Host/Java/JRE/Unmanaged/*");
errors = make_list();

if(empty_or_null(jre_installs))
  jre_installs = make_array();

# Only check bundled JREs if paranoid
bundled = get_kb_list("Host/Java/JRE/Bundled/*");
if (report_paranoia >= 2 && !empty_or_null(bundled)) {
  foreach bkey (keys(bundled)) {
    jre_installs[bkey] = bundled[bkey];
  }
}

if(empty_or_null(jre_installs))
  audit(AUDIT_KB_MISSING, "Host/Java/JRE/Unmanaged/*");

# For display
latest_versions = '1.8.0_111';

# Preformatted:
# Oldest supported version is 1.8.0_00 for 1.8 line
oldest_supp_version = '1.8.0.0';

# Longterm support data
longterm_support_lists = make_array(
 "^1\.[01]\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', 'No support dates are available.'
      ),
 # https://web.archive.org/web/20031001180548/http://java.sun.com/products/jdk/1.2/
 "^1\.2\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2003-12-02 (end of life)'
      ),
 "^1\.3\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2006-12-01 (end of life)' # Reached EOL on 1.6 release date
      ),
  "^1\.4\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2008-10-01 (end of regular support) / 2010-02-01 (end of Premier Support) / 2013-02-01 (end of Extended Support)"
      ),
  "^1\.5\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2009-10-01 (end of regular support) / 2011-05-01 (end of Premier Support) / 2015-05-01 (end of Extended Support)"
      ),
  "^1\.6\.", make_array(
        'support_type' , 'premier_support',
        'support_dates', "2013-02-01 (end of regular support) / 2015-12-01 (end of Premier Support) / 2018-12-01 (end of Extended Support)"
      ),
  "^1\.7\.", make_array(
        'support_type' , 'premier_support',
        'support_dates', "2015-03-01 (end of regular support) / 2019-07-01 (end of Premier Support) / 2022-07-01 (end of Extended Support)"
      )
#  "^1\.8\.", make_array(
#        'support_type' , 'extended_support',
#        'support_dates', "2017-09-01 (end of regular support) / 2022-03-01 (end of Premier Support) / 2025-03-01 (end of Extended Support)"
#      )
);

count = 0;
# See if any installs are unsupported...
foreach key (list_uniq(keys(jre_installs)))
{
  covered_by_premier_or_extended_support = FALSE;

  # gather
  matches = eregmatch(string:key, pattern:'/([0-9._]+)$');
  if (!isnull(matches))
    version = matches[1];
  else
    continue;

  # prepare
  raw_version = version;
  version = str_replace(string:version, find:"_", replace:".");

  dirs = make_list(get_kb_list(key));
  foreach dir (dirs)
  {
    # Before declaring a version unsupported,
    # check that it's not in Premier Support
    # and not in Extended Support
    foreach pattern (keys(longterm_support_lists))
    {
      if (version !~ pattern) continue;

      support_type  = longterm_support_lists[pattern]['support_type'];
      support_dates = longterm_support_lists[pattern]['support_dates'];

      if (support_type == "out_of_support")
        unsupported_date_report_string = support_dates;
      else
      {
        set_kb_item(
          name:"Java/JRE/"+support_type+"/"+dir+"/"+raw_version,
          value:support_dates
        );
        covered_by_premier_or_extended_support = TRUE;
      }
      break;
    }

    if (
      !covered_by_premier_or_extended_support &&
      ver_compare(ver:version, fix:oldest_supp_version, strict:FALSE) < 0
    )
    {
      count++;

      register_unsupported_product(product_name : 'Oracle Java JRE',
                                   version      : version,
                                   cpe_base     : "oracle:jre");

      report +=
        '\n  Path              : ' + dir +
        '\n  Installed version : ' + raw_version +
        '\n  Latest versions   : ' + latest_versions +
        '\n  Support dates     : ' + unsupported_date_report_string +
        '\n';
    }
  }
}

# ...then report on any that were found
if (strlen(report))
{
  if (report_verbosity > 0)
  {
    if (count > 1)
    {
      report =
        '\nThe following Java JRE installations are below version ' + oldest_supp_version +
        '\nand are unsupported :\n' + report;
    }
    else
    {
      report =
        '\nThe following Java JRE installation is below version ' + oldest_supp_version +
        '\nand is unsupported :\n' + report;
    }

    security_hole(port:0, extra:report);
  }
  else
    security_hole(0);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installations : \n  ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else
{
  if (strlen(report))
    exit(0);
  else
    audit(AUDIT_NOT_INST, "An unsupported version of Oracle Java JRE");
}
