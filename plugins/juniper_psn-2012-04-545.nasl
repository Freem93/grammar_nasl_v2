#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58874);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/08/28 13:51:52 $");
  script_osvdb_id(82824);

  script_name(english:"Juniper Junos SSH TACACS+ Incorrect Permissions (PSN-2012-04-545)");
  script_summary(english:"Checks version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device may grant permissions incorrectly."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Junos
running on the remote host may grant permissions incorrectly when SSH
sessions are authenticated remotely using TACACS+ for authentication
and authorization.  Fetched authorizations are stored in a file whose
name is based on process ID.  On unclean exits of the SSH client, this
file is not deleted, and therefore reused for future login sessions
with the same process ID.  This could result in authorizations being
applied to the wrong user."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-04-545&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85546a08");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-04-545."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/25");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");

fixes['10.1'] = '10.1R3';
fixes['10.2'] = '10.2R2';
fixes['10.3'] = '10.3R1';
fixes['10.4'] = '10.4R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);

