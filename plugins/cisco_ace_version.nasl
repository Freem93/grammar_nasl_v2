#TRUSTED 309e6664cc691a5566c481de5d762c2fbc7c57242e11f3f71f43f4a07794efa968be9e7d1756f60c26008c07c01cdf452afdd5f47fbbff5e2b206c1ebd6144bcf61e6fa4e6e2f53b79bbcb3fc5c531fee03d95a0269f0239879bde89987333cb87fc6f023314a6686e0f038018d538ad2e648fdf161a0c0e72d15b9ad2f7674ca48b91b84b9cee16ce147f7124bfc3d0c75ed65fdf3c29ecf4f18c8c2280d2d7e93981eb9a89688e6f23584be12e98293170b83fb7268390473355ba8300d91b8af9ec3640e1126a9098d0edf02ed33f072e87e256bfafad0a77cd2f6d79e0bdda411e5d8840f15541fb45123a219bbb604e7c2b8d6effffbf0496968fb53b9c91c85b57bca03ce383514346ac44012309c47dc98a92fc9a29cf0aaecd478490d4dd1c9002a59920226b40994ccc7e9afad1ab14f76a8ce284ae5984a8b461de1dea6426903e14227b970f3ceea44b17a80b750b1e40b8b410b2b58931e4019c26c37b0f4f0610a0f7fe0dd798c93640749dbf024f716baf378c7dcb243c59d324479595ee5cb184ccfb4c3e54ad6c92dd9feb834e1949ada867cf549d2ff2711f155e8469ece73f2725abbcf119edbd023f82ae43f690b105245ca779b3f9c94939b49161fc3c7bc1b1aac154c239fb80be68c14e6c7177a97bdd97b0ec7a894241e9f30a0e5e7462649d4020f8c7ee72b3572411fc67348d542dec5833a4e3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69912);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/01");

  script_name(english:"Cisco Application Control Engine (ACE) Version");
  script_summary(english:"Obtains the ACE version.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version of the Cisco Application Control
Engine (ACE) software installed on the remote Cisco device.");
  script_set_attribute(attribute:"description", value:
"Cisco Application Control Engine (ACE) software is installed on the
remote Cisco IOS or ACE device. It is a load-balancing and
application-delivery solution for Cisco Catalyst 6500 Series switches
and Cisco 7600 Series routers, and it is also available as an
appliance.");
  # https://www.cisco.com/c/en/us/products/interfaces-modules/ace-application-control-engine-module/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a80d18e9");
  # https://www.cisco.com/c/en/us/products/application-networking-services/product-listing.html#DataCenterApplicationServices
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d97a1e0e");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_control_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_ports("Host/Cisco/ACE/Version", "Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

model = NULL;

# nb: ssh_get_info.nasl can get version info with newer releases of ACE
#     by running "show version"; for other releases, we'll try to run
#     some additional commands.
version = get_kb_item("Host/Cisco/ACE/Version");
if (isnull(version))
{
  if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
  if (!get_kb_item("Host/Cisco/IOS/Version")) audit(AUDIT_OS_NOT, "Cisco IOS");

  failed_cmds = make_list();
  is_ace = FALSE;
  override = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
  if (!check_cisco_result(buf)) failed_cmds = make_list(failed_cmds, "show module");
  else if ("Application Control Engine Module" >< buf)
  {
    is_ace = TRUE;

    match = eregmatch(pattern:"\)ACE (A[0-9]+\([^\)]+\))", string:buf);
    if (!isnull(match)) version = match[1];
  }

  if (isnull(version))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
    if (!check_cisco_result(buf))
    {
      failed_cmds = make_list(failed_cmds, "show inventory");
      if (cisco_needs_enable(buf)) override = 1;
    }
    else if ('DESCR: "Application Control Engine Service Module"' >< buf)
    {
      is_ace = TRUE;

      match = eregmatch(pattern:"system:[ \t]+Version[ \t]+(A[0-9].+)[ \t]+\[build ", string:strstr(buf, "Software:"));
      if (!isnull(match)) version = match[1];
    }
  }

  if (max_index(failed_cmds) == 2) exit(1, "Failed to determine if Cisco ACE is installed.");
  if (!is_ace) audit(AUDIT_NOT_INST, "Cisco ACE");
  if (!version) exit(1, "Failed to extract the Cisco ACE version.");

  set_kb_item(name:"Host/Cisco/ACE/Version", value:version);
}
# Parse model from appliance
if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
  if (check_cisco_result(buf))
  {
    # Appliance
    pattern = 'DESCR: "ACE ([0-9]+) Application Control Engine Appliance"';
    match = eregmatch(pattern:pattern, string:buf);
    if (!isnull(match))
    {
      model = match[1];
      set_kb_item(name:"Host/Cisco/ACE/Model", value:model);
    }

    if (isnull(model))
    {
      # Module
      pattern = " PID: (ACE[0-9]+)-";
      match = eregmatch(pattern:pattern, string:buf);
      if (!isnull(match))
      {
        model = match[1];
        set_kb_item(name:"Host/Cisco/ACE/Model", value:model);
      }
    }
  }
}

if (report_verbosity > 0)
{
  report = NULL;
  if (!isnull(model)) report = '\n  Model   : ' + model;
  report += '\n  Version : ' + version +
            '\n';
  security_note(port:0, extra:report + cisco_caveat(override));
}
else security_note(port:0, extra:cisco_caveat(override));
