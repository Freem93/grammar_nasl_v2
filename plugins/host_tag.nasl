#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87413);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/23 20:09:08 $");

  script_name(english:"Host Tagging");
  script_summary(english:"Uniquely identifies the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin uniquely identifies the remote host.");
  script_set_attribute(attribute:"description", value:
"This plugin uniquely identifies the remote host by reading a UUID
from a file or by writing a UUID to a file. Tenable products, such as
Nessus Cloud and SecurityCenter, use this UUID for identifying scan
targets for more accurate historical results and license counts.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("host_tag_win.nbin", "host_tag_nix.nbin");

  exit(0);
}
