#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73531);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_name(english:"Unsupported Fortinet Operating System");
  script_summary(english:"Checks for EOL");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running an obsolete operating system.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote Fortinet operating system is
obsolete and is no longer maintained by Fortinet.

Lack of support implies that no new security patches for the operating
system will be released by the vendor. As a result, it is likely to
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.fortinet.com/Information/ProductLifeCycle.aspx");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a supported version of the applicable Fortinet operating
system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortianalyzer_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortimanager_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortiweb");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortimail");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("datetime.inc");

model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
now = unixtime();
device_supported = FALSE;

eol_version = NULL;
eol_date = NULL;

# Array of EOL devices, versions and dates.
eol = make_array(
  "forti(gate|wifi)", make_array(
    "^3\.3\.", make_list("2009-10-02", "3.0 MR 3"),
    "^3\.4\.", make_list("2009-12-29", "3.0 MR 4"),
    "^3\.5\.", make_list("2010-07-03", "3.0 MR 5"),
    "^3\.6\.", make_list("2011-02-04", "3.0 MR 6"),
    "^3\.7\.", make_list("2011-07-18", "3.0 MR 7"),
    "^4\.0\.", make_list("2012-02-24", "4.0"),
    "^4\.1\.", make_list("2012-08-24", "4.0 MR 1"),
    "^4\.2\.", make_list("2013-04-01", "4.0 MR 2"),
    "^4\.3\.", make_list("2017-03-19", "4.0 MR 3"),
    "^5\.0\.", make_list("2015-11-01", "5.0")
    ),
  "fortianalyzer", make_array(
    "^3\.3\.", make_list("2009-10-02", "3.0 MR 3"),
    "^3\.4\.", make_list("2010-01-12", "3.0 MR 4"),
    "^3\.5\.", make_list("2010-07-12", "3.0 MR 5"),
    "^3\.6\.", make_list("2011-02-04", "3.0 MR 6"),
    "^3\.7\.", make_list("2011-08-06", "3.0 MR 7"),
    "^4\.0\.", make_list("2012-02-25", "4.0"),
    "^4\.1\.", make_list("2012-08-24", "4.0 MR 1"),
    "^4\.2\.", make_list("2013-04-07", "4.0 MR 2"),
    "^4\.3\.", make_list("2014-06-30", "4.0 MR 3"),
    "^5\.0\.", make_list("2015-11-01", "5.0")
    ),
  "fortimanager", make_array(
    "^3\.3\.", make_list("2010-01-31", "3.0 MR 3"),
    "^3\.4\.", make_list("2010-03-09", "3.0 MR 4"),
    "^3\.5\.", make_list("2010-07-11", "3.0 MR 5"),
    "^3\.6\.", make_list("2011-02-11", "3.0 MR 6"),
    "^3\.7\.", make_list("2011-07-23", "3.0 MR 7"),
    "^4\.0\.", make_list("2012-03-12", "4.0"),
    "^4\.1\.", make_list("2012-09-11", "4.0 MR 1"),
    "^4\.2\.", make_list("2013-04-03", "4.0 MR 2"),
    "^4\.3\.", make_list("2014-06-30", "4.0 MR 3"),
    "^5\.0\.", make_list("2015-11-01", "5.0")
    ),
  "fortiweb", make_array(
    "^3\.1\.", make_list("2012-04-20", "3.1"),
    "^3\.2\.", make_list("2012-06-04", "3.2"),
    "^3\.3\.", make_list("2012-09-03", "3.0 MR 3"),
    "^4\.0\.", make_list("2013-03-12", "4.0"),
    "^4\.1\.", make_list("2013-08-03", "4.0 MR 1"),
    "^4\.2\.", make_list("2014-02-01", "4.0 MR 2"),
    "^4\.3\.", make_list("2014-08-01", "4.0 MR 3"),
    "^4\.4\.", make_list("2015-06-22", "4.0 MR 4")
    ),
  "fortimail", make_array(
    "^2\.8\.", make_list("2010-01-15", "2.8 MR 1"),
    "^3\.0\.", make_list("2010-08-03", "3.0"),
    "^3\.1\.", make_list("2010-11-01", "3.0 MR 1"),
    "^3\.2\.", make_list("2010-12-24", "3.0 MR 2"),
    "^3\.3\.", make_list("2011-04-18", "3.0 MR 3"),
    "^3\.4\.", make_list("2011-08-01", "3.0 MR 4"),
    "^3\.5\.", make_list("2012-05-07", "3.0 MR 5"),
    "^4\.0\.", make_list("2012-11-24", "4.0"),
    "^4\.1\.", make_list("2013-07-12", "4.0 MR 1"),
    "^4\.2\.", make_list("2014-03-11", "4.0 MR 2"),
    "^4\.3\.", make_list("2016-11-17", "4.0 MR 3"),
    "^5\.0\.", make_list("2016-02-28", "5.0"),
    "^5\.1\.", make_list("2016-12-19", "5.0 MR 1")
    )
  );

# Iterate through devices to determine appropriate EOL check.
foreach device (keys(eol))
{
  if (preg(string:model, pattern:device, icase:TRUE))
  {
    device_supported = TRUE;
    device_data = eol[device];
    break;
  }
}

# If device was not in the list, then exit with audit and we should add
# support for that device.
if (!device_supported) exit(0, model + " is not a supported device.");

# Iterate through versions to determine EOL date and finally check if
# date is earlier than today to flag as EOL.
foreach ver (keys(device_data))
{
  if (version =~ ver)
  {
    ver_data = device_data[ver];

    # Convert EOL date to unixtime for comparison.
    date = split(ver_data[0], sep:'-', keep:FALSE);
    date_unix = mktime(year: int(date[0]), mon: int(date[1]), mday: int(date[2]));

    if (date_unix < now)
    {
      eol_version = ver_data[1];
      eol_date = ver_data[0];
      break;
    }
  }
}

# Report if vulnerable.
if (eol_version && eol_date)
{
  port = 0;
  report = '\n' + model + " " + eol_version + " reached end of support on " + eol_date + '.\n';

  set_kb_item(name:'Host/OS/obsolete', value:TRUE);
  set_kb_item(name:'Host/OS/obsolete/text', value:report);

  register_unsupported_product(product_name:'Fortinet Fortios', cpe_class:CPE_CLASS_OS,
                               version:version, cpe_base:"fortinet:fortios");

  if (report_verbosity > 0) security_hole(extra:report, port:port);
  else security_hole(port:port);
  exit(0);
}
else exit(0, model + " " + version + " is still supported.");
