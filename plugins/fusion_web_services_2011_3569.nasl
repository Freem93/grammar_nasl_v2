#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58205);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2011-3569");
  script_bugtraq_id(51462);
  script_osvdb_id(78430);

  script_name(english:"Oracle Fusion Middleware Web Services Manager Unspecified Remote Information Disclosure");
  script_summary(english:"Checks version of Fusion Middleware products");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of one or more Fusion Middleware products installed on the
remote host indicates a susceptibility to an unspecified, remote
information disclosure attack related to the Web Services Manager
Security Component accessible via the HTTP protocol.");
  script_set_attribute(attribute:"solution", value:
"See the Oracle advisory for information on obtaining and applying bug
fix patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("fusion_weblogic_installed.nasl");
  script_require_keys("SMB/WebLogic_Fusion/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

info = "";
comps_vuln = 0;

get_kb_item_or_exit("SMB/WebLogic_Fusion/Installed");
installs = get_kb_list_or_exit("SMB/WebLogic_Fusion/*/Install_Num");

get_kb_item_or_exit('SMB/Registry/Enumerated');
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");

# Connect to IPC share on machine
#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

info = "";

function checkForFix(bugfix, patches)
{
  local_var patch;
  foreach patch (patches)
  {
    if (patch == bugfix)
       return TRUE;
  }
  return FALSE;
}

function compVerCheck(comp, xml)
{
  local_var res;
  res = eregmatch(pattern:'<COMP NAME="' + comp + '" VER="([0-9\\.]+)"', string:xml);
  if (!isnull(res[1]))
    return make_list(res[0], res[1]);
  else
    return NULL;
}

oracle_common_found = FALSE;

foreach install_num (installs)
{
  middleware_path = get_kb_item("SMB/WebLogic_Fusion/" + install_num + "/FusionPath");
  oracle_homes = get_kb_list("SMB/WebLogic_Fusion/" + install_num + "/comp_homes/*");
  common_patches = NULL;
  fixes_required = make_array();

  foreach home (oracle_homes)
  {
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:home);
    xml_file = ereg_replace(pattern:"^[A-Za-z]:(.*)\\?", replace:"\1\inventory\ContentsXML\comps.xml", string:home);

    NetUseDel(close:FALSE);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(1, "Can't connect to '" + share + "' share.") ;
    }

    fh = CreateFile(
      file:xml_file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if (isnull(fh))
    {
      NetUseDel();
      exit(1, "Unable to open inventory/ContentsXML/comps.xml for Oracle home located at " + home + ".");
    }

    length = GetFileSize(handle:fh);
    chunk_size = 1024;
    os = 0;
    xml_content = "";

    # since these can be a little lengthy (upwards of 500k),
    # reading these files in chunks is more reliable
    while(TRUE)
    {
      len_to_read = chunk_size;
      if (os + chunk_size > length)
        len_to_read = length - os;
      if (len_to_read > 0)
      {
         chunk = ReadFile(handle:fh, length:len_to_read, offset:os);
         if (isnull(chunk) || strlen(chunk) != len_to_read)
         {
           NetUseDel();
           exit(1, "Error reading contents of comps.xml from Oracle home located at " + home + ".");
         }
         xml_content += chunk;
         os += len_to_read;
      }
      if (len_to_read < chunk_size)
        break;
    }

    CloseFile(handle:fh);
    if (xml_content == "")
    {
      NetUseDel();
      exit(1, "Unable to obtain contents of registry.xml for Fusion Middleware installed at " + middleware_path + ".");
    }

    bugs_fixed = make_list();
    foreach line (split(xml_content, sep:'\n', keep:FALSE))
    {
      item = eregmatch(pattern:"<BUG>([0-9]+)</BUG>", string:line);
      if (!isnull(item[1]))
        bugs_fixed = make_list(bugs_fixed, item[1]);
    }
    bugs_fixed = list_uniq(bugs_fixed);

    if ("oracle_common" >< home)
    {
      common_patches = bugs_fixed;
      oracle_common_found = TRUE;
      continue;
    }
    ver = NULL;
    ver = compVerCheck(comp: 'oracle.as.soa.top', xml:xml_content);
    if (isnull(ver))
      ver = compVerCheck(comp: 'oracle.as.webcenter.top', xml:xml_content);
    if (isnull(ver))
      ver = compVerCheck(comp: 'oracle.as.im.top', xml:xml_content);
    if (isnull(ver))
      ver = compVerCheck(comp: 'oracle.as.webtiercd.top', xml:xml_content);
    if (isnull(ver))
       ver = compVerCheck(comp: 'oracle.classicwls.top', xml:xml_content);
    if (!isnull(ver))
    {
      if(ver[1] == "11.1.1.3.0")
      {
        bugfix = '13113580';
        if (get_kb_item("SMB/WebLogic_Fusion/" + install_num + "/bugfixes/" + bugfix))
          continue;
        if (checkForFix(bugfix: bugfix, patches: bugs_fixed))
          continue;
        fixes_required[home] = make_list(bugfix, ver[1], ver[0]);
      }
      if (ver[1] == "11.1.1.4.0")
      {
        bugfix = '13113594';
        if (get_kb_item("SMB/WebLogic_Fusion/" + install_num + "/bugfixes/" + bugfix))
          continue;
        if (checkForFix(bugfix: bugfix, patches: bugs_fixed))
          continue;
        fixes_required[home] = make_list(bugfix, ver[1], ver[0]);
      }
      if (ver[1] == "11.1.1.5.0" || ver[1] == "11.1.1.2.0")
      {
        # the 11.1.1.2 check is only for forms and reports
        if (ver[1] == "11.1.1.2.0" && comp != 'oracle.classicwls.top')
          continue;
        bugfix = '13113602';
        if (get_kb_item("SMB/WebLogic_Fusion/" + install_num + "/bugfixes/" + bugfix))
          continue;
        if (checkForFix(bugfix: bugfix, patches: bugs_fixed))
          continue;
        fixes_required[home] = make_list(bugfix, ver[1], ver[0]);
      }
    }
  }


  # final patch check and report info generation
  foreach home (keys(fixes_required))
  {
    comps_vuln ++;
    fix_info = fixes_required[home];
    if (!checkForFix(bugfix: fix_info[0], patches: common_patches))
    {
      info += '\n\n Middleware home  : ' + middleware_path;
      info += '\n   Component home  : ' + home;
      info += '\n   Version source  : ' + fix_info[2];
      info += '\n   Version         : ' + fix_info[1];
      info += '\n   Bugfix required : ' + fix_info[0];
    }
  }
}

# Cleanup
NetUseDel();

if (!oracle_common_found)
  exit(0, "No affected products are installed.");

if (comps_vuln > 0)
{
  set_kb_item(name:"SMB/WebLogic_Fusion/Installed", value:TRUE);
  if (comps_vuln == 1)
    report = '\nThe following affected Fusion Middleware component was found :' + info + '\n';
  else
    report = '\nThe following affected Fusion Middleware components were found :' + info + '\n';

  if (report_verbosity > 0)
    security_warning(port:port, extra:report);
  else security_warning(port);

  exit(0);
}
else exit(0, "No affected Middleware Fusion installs were found.");
