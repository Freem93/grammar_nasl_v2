#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include( 'compat.inc' );

if(description)
{
  script_id(10917);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/17 18:46:05 $");

  script_name(english:"SMB Scope");
  script_summary(english:"SMB scope options");

  script_set_attribute(
    attribute:'synopsis',
    value:'This plugin configures certain SMB settings for use with other plugins.'
  );

  script_set_attribute(
    attribute:'description',
    value:
'This plugin configures Nessus so that it knows if it should query
local information on each host or information pertaining to the domain
(ie: requests will be forwarded to the PDC). 

If you test a single workstation, you want information about the
domain.  If you test the whole network, including the PDC, you won\'t
want redundant information. 

See the plugins preferences panel for details.'
  );
  script_set_attribute(attribute:'solution', value:'n/a');
  script_set_attribute(attribute:'risk_factor', value:'None');

  script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/17");
  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_category(ACT_SETTINGS);
  script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
  script_family(english:"Settings");

  script_add_preference(name:"Request information about the domain", type:"checkbox", value:"yes");
  exit(0);
}

x =  script_get_preference("Request information about the domain");

if((x == "yes"))
{
 set_kb_item(name:"SMB/test_domain", value:TRUE);
}
