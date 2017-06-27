#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(63067);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_bugtraq_id(56610);
  script_osvdb_id(87619);
  script_xref(name:"CERT", value:"849841");
  script_xref(name:"IAVB", value:"2012-B-0117");

  script_name(english:"Symantec Mail Security Autonomy Verity Keyview Filter Vulnerabilities (SYM12-018)");
  script_summary(english:"Checks version of Symantec Mail Security");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a mail security application installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The file attachment filter component included with the instance of
Symantec Mail Security installed on the remote Windows host is
reportedly affected by multiple, unspecified code execution
vulnerabilities that can be triggered when handling attachments of
various types. 

By sending an email with a specially crafted attachment through a
vulnerable server, an attacker could execute arbitrary code subject to
the privileges under which the affected daemon runs.");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20121120_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84141df1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Mail Security for Microsoft Exchange 6.5.8 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("sms_for_msexchange.nasl");
  script_require_ports("SMB/SMS_Exchange/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/SMS_Exchange/Version");
path = get_kb_item_or_exit("SMB/SMS_Exchange/Path");

fixed_version = '6.5.8';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item('SMB/transport');
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Mail Security for Microsoft Exchange', version, path);
