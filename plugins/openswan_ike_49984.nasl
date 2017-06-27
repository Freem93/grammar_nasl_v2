#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81052);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/29 15:43:36 $");

  script_cve_id("CVE-2011-3380");
  script_bugtraq_id(49984);
  script_osvdb_id(76100);

  script_name(english:"Openswan < 2.6.36 IKE Packet NULL Pointer Dereference Remote DoS");
  script_summary(english:"Checks IKE Device ID for a vulnerable Openswan version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Openswan prior to version
2.6.36. It is, therefore, affected by a remote denial of service
vulnerability due to a NULL pointer dereference flaw. A remote
attacker, using a specially crafted ISAKMP message with an invalid
KEY_LENGTH attribute, can cause a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://download.openswan.org/openswan/CVE-2011-3380/CVE-2011-3380.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Openswan 2.6.36 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openswan:openswan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_require_ports("Services/udp/ikev1", "Services/udp/ikev2", 500);
  script_dependencies("ike2_detect.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

vuln_start = "2.6.29";
vuln_end = "2.6.35";
fixed = "2.6.36";

port = get_kb_item("Services/udp/ikev1");
if (empty_or_null(port)) port = get_kb_item("Services/udp/ikev2");
if (empty_or_null(port)) audit(AUDIT_NOT_DETECT,"ikev1 or ikev2");

kb_list = get_kb_list("Services/ike/*");
kb2_list = get_kb_list("Services/ike2/*");

# Combine both IKE and IKEv2 results into one list
list = "";
if (! isnull(kb2_list))
{
  if (! isnull(kb_list))
  {
    list = keys(kb_list);
    list = make_list(list, keys(kb2_list));
  }
  else
  {
    list =  keys(kb2_list);
  }
}
else
{
  if (! isnull(kb_list)) list = keys(kb_list);
  else
  {
    audit(AUDIT_KB_MISSING, "Services/ike/* and Services/ike2/*");
  }
}

# Check if it was Openswan and which version found.
software = "";
version = "";

foreach  item (list)
{
  if (preg(pattern:"Openswan [0-9.]+",string:item,icase:TRUE))
  {
    foreach ike_name_ver_kb (split(item,sep:' '))
    {
      if (preg(pattern:"\/Openswan",string:ike_name_ver_kb,icase:TRUE))
      {
        path = split(ike_name_ver_kb,sep:'/');
        software = path[2];
      }
      else if (preg(pattern:"[0-9.]+",string:ike_name_ver_kb))
        version = ike_name_ver_kb;
    }
  }
}

# Check if we have the software name
if (empty_or_null(software))
  audit(AUDIT_NOT_INST, "Openswan");

# Check if the version was found.
if (empty_or_null(version))
  audit(AUDIT_UNKNOWN_APP_VER, "Openswan");

vuln = TRUE;
# Software vuln if between 2.6.29 - 2.6.35
if (ver_compare(ver:version, fix:fixed, strict:FALSE) >= 0)
{
  vuln = FALSE;
}
else if (ver_compare(ver:version, fix:vuln_start, strict:FALSE) < 0)
{
  vuln = FALSE;
}
else vuln = TRUE;

report = "";
if (vuln)
{
  report += software + " is vulnerable to a denial of service attack." + '\n';
  report += "Version found was "+version+'\n';
  report += '\n';
  report += "Update to "+software+" version " + fixed + " or later."+'\n';
}

if (report)
{
  register_service(port:port, ipproto:"udp", proto:"openswan");
  if (report_verbosity > 0) security_warning(port:port, proto:'udp', extra:report);
  else security_warning(port:port, proto:'udp');
}
else audit(AUDIT_HOST_NOT, "affected");
