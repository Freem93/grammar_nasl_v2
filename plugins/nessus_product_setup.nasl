#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(83955);
 script_version("$Revision: 1.3 $");
 script_cvs_date("$Date: 2017/01/11 17:46:27 $");

 script_name(english:"Nessus Product Information");
 script_summary(english:"Initializes information used in Nessus product detection.");

 script_set_attribute(attribute:"synopsis", value:
"Set up information about which Nessus product is running.");
 script_set_attribute(attribute:"description", value:
"Set up Nessus product information to help facilitate some plugins to
detect what platform they are running on.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");

 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_INIT);

 script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 exit(0);
}
include("global_settings.inc");
include("misc_func.inc");
include("nessusd_product_info.inc");

report = "Nessus product is ";

# nessus environment
env = nessusd_env();

if (!isnull(env['product']))
{
  if (env['product'] == PRODUCT_WIN_AGENT) report += 'Windows Agent.\n';
  else if (env['product'] == PRODUCT_UNIX_AGENT)
  {
    if (env['os'] == 'DARWIN')
    {
      env['product'] = PRODUCT_MAC_AGENT;
      report += 'Mac Agent.\n';
    }
    else
      report += 'Unix Agent.\n';
  }
  else if (env['product'] == PRODUCT_NESSUSD) report += 'Nessus Scanner.\n';
  else if (env['product'] == PRODUCT_NESSUSD_NSX) report += 'Nessus NSX Scanner.\n';

  else report += 'undetermined.\n';
}
else
{
  report = 'No Nessus Product information available.\n';
}

set_kb_item(name:"nessus/product", value:env['product']);
set_kb_item(name:"nessus/os", value:env['os']);

# Agent bool set
if (nessusd_is_agent()) set_kb_item(name:"nessus/product/agent", value:TRUE);

# local scan set
if (nessusd_is_local()) set_kb_item(name:"nessus/product/local", value:TRUE);

exit(0, report);
