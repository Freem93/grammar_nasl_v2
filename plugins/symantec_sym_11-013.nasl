#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(56666);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id(
    "CVE-2011-0337",
    "CVE-2011-0338",
    "CVE-2011-0339",
    "CVE-2011-1213",
    "CVE-2011-1214",
    "CVE-2011-1215",
    "CVE-2011-1216",
    "CVE-2011-1218",
    "CVE-2011-1512"
  );
  script_bugtraq_id(
    48016,
    48017,
    48018,
    48019,
    48020,
    48021,
    49898,
    49899,
    49900
  );
  script_osvdb_id(
    72705,
    72706,
    72707,
    72708,
    72709,
    72711,
    76112,
    76113,
    76114
  );

  script_name(english:"Symantec Mail Security Autonomy Verity Keyview Filter Vulnerabilities (SYM11-013)");
  script_summary(english:"Checks version of Symantec Mail Security");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a mail security application installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The file attachment filter component included with the instance of
Symantec Mail Security installed on the remote Windows host is
reportedly affected by multiple buffer overflow vulnerabilities that can
be triggered when handling attachments of various types. 

By sending an email with a specially crafted attachment through a
vulnerable server, an attacker could execute arbitrary code subject to
the privileges under which the affected daemon runs.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64c5b7df");
  script_set_attribute(attribute:"solution", value:
"If using Symantec Mail Security for Domino, upgrade to version 7.5.12 /
8.0.9. 

If using Symantec Mail Security for Microsoft Exchange, upgrade to
version 6.0.13 / 6.5.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Lotus Notes 8.0.x - 8.5.2 FP2 - Autonomy Keyview (.lzh Attachment)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/28");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("sms_for_domino.nasl", "sms_for_msexchange.nasl");
  script_require_keys("Symantec_Mail_Security/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("Symantec_Mail_Security/Installed");

dirs = make_list("Domino", "Exchange");

# Ensure that the affected software is installed.
backend = NULL;
foreach type (dirs)
{
  if (get_kb_item("SMB/SMS_" + type + "/Installed"))
  {
    backend = type;
    break;
  }
}
if (isnull(backend) || (backend != 'Exchange' && backend != 'Domino')) exit(0, "Neither Symantec Mail Security for Domino nor Exchange is installed on the remote host.");

path = get_kb_item_or_exit("SMB/SMS_" + type + "/Path");
version = get_kb_item_or_exit("SMB/SMS_" + type + "/Version");

if (
  (
    backend == 'Exchange' &&
    (
      (version =~ '^6\\.0\\.' && ver_compare(ver:version, fix:'6.0.13', strict:FALSE) == -1) ||
      (version =~ '^6\\.[1-5]\\.' && ver_compare(ver:version, fix:'6.5.6', strict:FALSE) == -1)
    )
  ) ||
  (
    backend == 'Domino' &&
    (
      (version =~ '^7\\.5\\.' && ver_compare(ver:version, fix:'7.5.12', strict:FALSE) == -1) ||
      (version =~ '^8\\.' && ver_compare(ver:version, fix:'8.0.9', strict:FALSE) == -1)
    )
  )
)
{
  # Report our findings.
  if (report_verbosity > 0)
  {
    if (backend == 'Exchange') fix = '6.0.13 / 6.5.6';
    else fix = '7.5.12 / 8.0.9';
    report =
      '\n  Product           : Symantec Mail Security for ' + backend +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The Symantec Mail Security for '+backend+' '+version+' install on the host is not affected.');
