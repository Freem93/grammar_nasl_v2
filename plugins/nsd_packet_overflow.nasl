#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38850);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_bugtraq_id(35029);
  script_xref(name:"Secunia", value:"35165");

  script_name(english:"NSD packet.c Off-By-One Remote Overflow");
  script_summary(english:"Checks the NSD version number");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host has a remote buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of NSD
running on the remote host has a stack-based buffer overflow
vulnerability. This could allow a remote attacker to overwrite one
byte in memory, leading to a denial of service. It is possible, but
unlikely, that this vulnerability could result in remote code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.nlnetlabs.nl/publications/NSD_vulnerability_announcement.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NSD version 3.2.2 or later, or apply the patch referenced
in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("nsd_version.nasl");
  script_require_keys("nsd/version", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item("nsd/version");
if (isnull(version)) exit(0);

ver_fields = split(version, sep:".", keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions >= 2.0.0 and < 3.2.2 are affected
if (
    major == 2 ||
    (major == 3 && (minor < 2 || (minor == 2 && rev < 2)))
) security_warning(port:53, proto:"udp");

