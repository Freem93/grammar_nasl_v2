#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60153);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/20 16:51:15 $");

  script_cve_id("CVE-2012-2978");
  script_bugtraq_id(54606);
  script_osvdb_id(84097);
  script_xref(name:"CERT", value:"624931");

  script_name(english:"NSD query_add_optional() Function NULL Pointer Dereference Malformed DNS Packet Parsing Remote DoS");
  script_summary(english:"Checks the NSD version number");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is affected by a denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of NSD
running on the remote host is affected by a denial of service
vulnerability because it fails to properly handle specially crafted
DNS packets.  This issue occurs because of a NULL pointer dereference
error in the 'query.c' source file.

Note that Nessus has only relied on the version itself and has not
attempted to determine whether the patches have been applied.");

  script_set_attribute(attribute:"see_also", value:"http://www.nlnetlabs.nl/downloads/CVE-2012-2978.txt");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to NSD version 3.2.12 or later or apply the patch
referenced in the project's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("nsd_version.nasl");
  script_require_keys("nsd/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item("nsd/version");
if (isnull(version)) exit(0, "The version of NSD listening on UDP port 53 is unknown.");

ver_fields = split(version, sep:".", keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions 3.x < 3.2.12 are affected
if (
  (major == 3 && minor < 2) ||
  (major == 3 && minor == 2 && rev < 12)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.2.12\n';
    security_warning(port:53, proto:"udp", extra:report);
  }
  else security_warning(port:53, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "NSD", 53, version, "UDP");
