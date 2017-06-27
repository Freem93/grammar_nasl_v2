#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85270);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/08/07 18:42:45 $");

  script_name(english:"Junos Operating System On Extended Support");
  script_summary(english:"Checks if operating system is on extended support.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an operating system that is on extended
support.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote Junos operating system has
transitioned to an extended portion in its support life cycle.
Continued access to new security updates requires a support service
contract; without one, the host likely will be missing security
updates.");
  script_set_attribute(attribute:"solution", value:
"Ensure that the host subscribes to the vendor's extended support
service contract and continues to receive security updates.");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/support/eol/junos.html");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("junos_unsupported.nasl");
  script_require_keys("Host/Juniper/JUNOS/extended_support");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

kb = get_kb_item_or_exit("Host/Juniper/JUNOS/extended_support");
if (report_verbosity > 0) security_note(port:0, extra:kb);
else security_note(0);
