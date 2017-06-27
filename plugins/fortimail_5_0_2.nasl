#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85514);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/19 14:23:08 $");

  script_osvdb_id(125024);

  script_name(english:"Fortinet FortiMail < 4.3.7 / 5.0.x < 5.0.2 Fragmented IPv6 Packet Handling DoS");
  script_summary(english:"Checks the version of Fortinet FortiMail.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description",value:
"The version of Fortinet FortiMail installed on the remote host is
prior to 4.3.7 / 5.0.2. It is, therefore, affected by a denial of service
vulnerability due to improper handling of fragmented IPv6 packets. A
remote attacker can exploit this to crash the kernel, resulting in
rebooting the device.");
  # http://kb.fortinet.com/kb/microsites/search.do?cmd=displayKC&docType=kc&externalId=FortiMail-v502-Release-Notespdf
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?ed013748");
  # http://docs.fortinet.com/uploaded/files/1858/FortiMail-v4.3.7-Release-Notes.pdf
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?c77dd1f8");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Fortinet FortiMail version 4.3.7 / 5.0.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2013/09/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2013/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:fortinet:fortimail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiMail";
model    = get_kb_item_or_exit("Host/Fortigate/model");
version  = get_kb_item_or_exit("Host/Fortigate/version");

# Make sure device is FortiMail.
if (!preg(string:model, pattern:"fortimail", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

if (version =~ "^5\.0\.") fix = "5.0.2";
else if (version =~ "^[1-4]\.") fix = "4.3.7";
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
