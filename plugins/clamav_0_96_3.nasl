#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49712);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/25 02:11:20 $");

  script_cve_id("CVE-2010-0405", "CVE-2010-3434");
  script_bugtraq_id(43331, 43555);
  script_osvdb_id(68167, 68302);
  script_xref(name:"Secunia", value:"41503");
  script_xref(name:"IAVB", value:"2010-B-0083");

  script_name(english:"ClamAV < 0.96.3 Multiple Vulnerabilities");
  script_summary(english:"Checks response to a clamd VERSION command");

  script_set_attribute(attribute:"synopsis", value:"The remote antivirus service is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its version, the clamd antivirus daemon on the remote
host is earlier than 0.96.3. Such versions are reportedly affected by
multiple vulnerabilities :

  - There is a failure to properly parse a specially crafted
    PDF file because of insufficient bounds-checks on PDF
    files in the 'find_stream_bounds()' function of the
    libclamav 'pdf.c' source file. (Bug 2226)

  - An integer overflow can be triggered in the
    'BZ2_decompress' function when parsing specially crafted
    BZ2 files, which could cause the server to crash or
    potentially allow execution of arbitrary code. (Bugs
    2230, 2231)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=2226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=2230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=2231");
  # https://github.com/vrtadmin/clamav-devel?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b29d7b20");
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.96.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# nb. banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("Antivirus/ClamAV/version");

port = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);


# Check the version number.
#
# nb: versions like 0.94rc1 are possible.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (
    ver[0] == 0 &&
    (
      ver[1] < 96 ||
      (ver[1] == 96 && ver[2] < 3)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    fixed_version = "0.96.3";

    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The remote host is not affected since ClamAV version " + version + " is installed.");
