#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 6900) exit(0);

include("compat.inc");

if (description)
{
  script_id(96797);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/15 16:58:55 $");

  script_name(english:"Host Asset Information");
  script_summary(english:"Displays information about the scan.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus collected information about the network interfaces, installed
software, users, and user groups on the target host.");
  script_set_attribute(attribute:"description", value:
"Nessus collected information about the target host's network
interfaces, including IPv4 addresses, IPv6 addresses, MAC addresses,
FQDNs, etc. An inventory of installed software was collected. Also,
information about users and user groups has been harvested. This data
has been stored in the Nessus report database.

Note that this plugin will not produce a visible report in the Nessus
user interface.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_exclude_keys("Host/dead");

  exit(0);
}

include("agent.inc");
include("misc_func.inc");
include("global_settings.inc");
include("install_func.inc");
include("rpm.inc");

if(get_kb_item("Host/dead") == TRUE) exit(0, "Host is offline.");

# Without this function, the plugin does nothing useful
if (!defined_func("report_tag_internal"))
  exit(0, "Function report_tag_internal() not defined in this version of Nessus.");

function enumerate_interfaces()
{
  local_var iface_list, interfaces, iface;
  local_var mac, ipv4_list, ipv6_list, ip_list;
  local_var aliased, virtual, is_target, kb_prefix, hostname_f;
  local_var fqdn, i, ipv4, ipv6;

  iface_list = get_kb_list("Host/iface/id");

  if (empty_or_null(iface_list))
    return "Not Collected";

  interfaces = make_nested_array();

  foreach iface (iface_list)
  {
    if (!empty_or_null(iface))
    {
      mac = NULL;
      ipv4_list = NULL;
      ipv6_list = NULL;
      ip_list = NULL;
      aliased = NULL;
      virtual = NULL;

      is_target = FALSE;
      fqdn = NULL;

      kb_prefix = "Host/iface/"+iface;
      mac = get_kb_item(kb_prefix+"/mac");
      ipv4_list = get_kb_list(kb_prefix+"/ipv4");
      ipv6_list = get_kb_list(kb_prefix+"/ipv6");
      aliased = get_kb_item(kb_prefix+"/aliased");
      virtual = get_kb_item(kb_prefix+"/virtual");

      interfaces[iface] = make_nested_array();

      # mac address
      if (!empty_or_null(mac))
        interfaces[iface]['mac address'] = mac;

      # ip addresses
      ip_list = make_nested_list();
      i = 0;
      if (!empty_or_null(ipv4_list))
      {
        foreach ipv4 (ipv4_list)
        {
          if (ipv4 == get_host_ip()) is_target = TRUE;
          ip_list[i++] = make_array('type', 'ipv4','value', ipv4);
        }
      }
      if (!empty_or_null(ipv6_list))
      {
        foreach ipv6 (ipv6_list)
        {
          ip_list[i++] = make_array('type', 'ipv6','value', ipv6);
        }
      }
      if (len(ip_list) > 0)
        interfaces[iface]['ip addresses'] = ip_list;

      # aliased
      if (!empty_or_null(aliased))
        interfaces[iface]['aliased'] = aliased;

      # virtual
      if (!empty_or_null(virtual))
        interfaces[iface]['virtual'] = virtual;

      if (is_target)
      {
        # set FQDN for scan target's interface only
        if (agent())
        {
          fqdn = get_kb_item("Host/agent/FQDN");
          if (isnull(fqdn)) fqdn = agent_fqdn();
        }
        else
        {
          fqdn = get_kb_item("Host/FQDN");
          if (isnull(fqdn)) fqdn = get_host_fqdn();
        }

        # validate fqdn
        if (empty_or_null(fqdn) ||
          fqdn == get_host_ip() ||
          fqdn !~ "^[A-Za-z0-9]+((\.|-)[A-Za-z0-9]+)*\.[A-Za-z]{2,}$"
        )
          fqdn = NULL;

        if (!isnull(fqdn))
          interfaces[iface]['fqdn'] = fqdn;
      }
    }
  }

  if (!empty_or_null(interfaces))
  {
    interfaces = make_nested_array("interfaces", interfaces);
    report_tag_internal(hostname:get_host_name(), tag:"interfaces", value:interfaces);
  }
}

function enumerate_software()
{
  local_var os;
  local_var installed_kbs, key;
  local_var sw_inventory, app;
  local_var installs, install, app_paths;
  local_var display_names, version, install_date, install_location, res;
  local_var distro, distros, pkg_mgr, packages, package;
  local_var oracle_homes, ohome, components, component;

  distros = make_list(
    "Host/AIX/lslpp",
    "Host/AmazonLinux/rpm-list",
    "Host/CentOS/rpm-list",
    "Host/Debian/dpkg-l",
    "Host/FreeBSD/pkg_info",
    "Host/Gentoo/qpkg-list",
    "Host/HP-UX/swlist",
    "Host/MacOSX/packages",
    "Host/Mandrake/rpm-list",
    "Host/McAfeeLinux/rpm-list",
    "Host/OracleVM/rpm-list",
    "Host/RedHat/rpm-list",
    "Host/Slackware/packages",
    "Host/Solaris/showrev",
    "Host/Solaris11/pkg-list",
    "Host/SuSE/rpm-list",
    "Host/VMware/esxupdate",
    "Host/VMware/esxcli_software_vibs",
    "Host/XenServer/rpm-list",
    "Host/Junos_Space/rpm-list"
  );

  sw_inventory = make_nested_array();
  app_paths = make_array();  # Used to track already detected paths and minimize duplication

  # We need to know the OS to do a thorough inventory of software
  os = get_kb_item("Host/OS");

  # Gather a list of software found via direct detection
  installed_kbs = get_kb_list("installed_sw/*");
  if (!empty_or_null(installed_kbs))
  {
    sw_inventory = make_nested_array();
    foreach app (sort(keys(installed_kbs)))
    {
      # This avoids reporting on webapps
      if (app =~ "^installed_sw\/[0-9]+\/$")
        continue;
      if (app =~ "^installed_sw\/[^\/]+$")
      {
        # Initialize the package object
        sw_inventory[app] = make_nested_array();
        foreach install (installs[1])
        {
          app_paths[install["path"]] = TRUE;
          sw_inventory[app]["path"] = install["path"];
          sw_inventory[app]["version"] = install["version"];
          if (!empty_or_null(install["display_version"]))
            sw_inventory[app]["display_version"] = install["display_version"];
          if (!empty_or_null(install["extra"]))
            sw_inventory[app]["extra"] = install["extra"];
          if (!empty_or_null(install["extra_no_report"]) && !empty_or_null(install["extra_no_report"]["method"]))
            sw_inventory[app]["method"] = install["extra_no_report"]["method"];
          else
            sw_inventory[app]["method"] = "direct";
        }
      }
    }
  }

  # Windows software enumeration
  if ("windows" >< tolower(os))
  {
    # Gather a list of software found via registry enumeration
    display_names = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
    if (!empty_or_null(display_names))
    {
      foreach key (sort(keys(display_names)))
      {
        app = display_names[key];
        if ("hotfix" >< tolower(app) || tolower(app) =~ "update.*kb")
          continue;
        key = key - "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/";
        key = key - "/DisplayName";

        # Make sure this isn't a duplicate we have already seen
        if (empty_or_null(sw_inventory[app]))
        {
          version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/"+key+"/DisplayVersion");
          install_date = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/"+key+"/InstallDate");
          install_location = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/"+key+"/InstallLocation");

          sw_inventory[app] = make_nested_array();
          if (!empty_or_null(version))
            sw_inventory[app]["version"] = version;
          if (!empty_or_null(install_location))
            sw_inventory[app]["path"] = install_location;
          if (!empty_or_null(install_date))
            sw_inventory[app]["install_date"] = install_date;
          sw_inventory[app]["detection_method"] = "registry";
        }
      }
    }
  }
  else
  {
    if ('solaris 10' >< tolower(os))
    {
      packages = get_kb_list("Solaris/Packages/Versions/*");
      if (!empty_or_null(packages))
      {
        foreach package (keys(packages))
        {
          package = package - "Solaris/Packages/Versions/";
          sw_inventory[package] = make_array();
          sw_inventory[package]["version"] = packages[package];
          sw_inventory[package]["method"] = "pkginfo -x";
        }
      }
    }
    else if ('slackware' >< tolower(os))
    {
      packages = get_kb_item("Host/Slackware/packages");
      foreach package (split(packages, sep:'\n', keep:FALSE))
      {
        res = eregmatch(string:package, pattern: "^(.+)-([^-]+)-([^-]+)-([^-]+)$");
        if (!empty_or_null(res))
        {
          sw_inventory[res[1]] = make_array();
          sw_inventory[res[1]]["version"] = res[2];
          sw_inventory[res[1]]["method"] = "package log";
        }
      }
    }
    foreach pkg_mgr (distros)
    {
      packages = get_kb_item(pkg_mgr);
      if (!empty_or_null(packages))
      {
        pkg_mgr = ereg_replace(pattern:'^.*/.*/(.*)', replace:"\1", string:pkg_mgr);
        switch (pkg_mgr)
        {
          case "rpm-list":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              res = parse_rpm_name(rpm:package);
              if (!empty_or_null(res["name"]))
              {
                sw_inventory[res["name"]] = make_array();
                if (!empty_or_null(res["version"]))
                  sw_inventory[res["name"]]["version"] = res["version"];
                if (!empty_or_null(res["release"]))
                  sw_inventory[res["name"]]["version"] += res["release"];
                sw_inventory[res["name"]]["method"] = "rpm -qa";
              }
            }
            break;
          case "dpkg-l":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              res = eregmatch(string:package, pattern:'^([uirph][nicufhWt])\\s+([^\\s]+)\\s+([^\\s]+)\\s+(.*)');
              if (!empty_or_null(res))
              {
                sw_inventory[res[2]] = make_array();
                sw_inventory[res[2]]["version"] = res[3];
                sw_inventory[res[2]]["description"] = res[4];
                sw_inventory[res[2]]["extra"] = make_array("status", res[1]);
                sw_inventory[res[2]]["method"] = "dpkg -l";
              }
            }
            break;
          case "lslpp":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              res = split(package, sep:':', keep:FALSE);
              if (max_index(res) > 0)
              {
                sw_inventory[res[1]] = make_array();
                sw_inventory[res[1]]["version"] = res[2];
                if (res[7] =~ '^[^\\s+]')
                  sw_inventory[res[1]]["description"] = res[7];
                sw_inventory[res[1]]["method"] = "lslpp";
              }
            }
            break;
          case "pkg_info":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              local_var pkg_desc = '';
              res = eregmatch(string:package, pattern:'^([^\\s]+)\\s+(.*)$');
              if (!empty_or_null(res))
              {
                pkg_desc = res[2];
                res = split(res[1], sep:"-", keep:FALSE);

                if (!empty_or_null(res))
                {
                  local_var pkg_name = res[0];
                  local_var index;
                  for (index = 1; index < max_index(res) - 1; index++)
                  {
                    pkg_name += "-" + res[index];
                  }

                 sw_inventory[pkg_name] = make_array();
                 sw_inventory[pkg_name]["version"] = res[index];
                 if (!empty_or_null(pkg_desc))
                   sw_inventory[pkg_name]["description"] = pkg_desc;
                 sw_inventory[pkg_name]["method"] = "pkg_info";
                }
              }
            }
            break;
          case "qpkg-list":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              res = eregmatch(string:package, icase:1, pattern:'(^[a-z0-9-]+)/([A-Za-z0-9\\+\\-]+)-(.*)');
              if (!empty_or_null(res))
              {
                pkg_name = res[1] + "/" + res[2];
                sw_inventory[pkg_name] = make_array();
                sw_inventory[pkg_name]["version"] = res[3];
                sw_inventory[pkg_name]["method"] = "qpkg-list";
              }
            }
            break;
          case "swlist":
            packages = split(packages, sep:'\n', keep:FALSE);
            for (index = 5; index < len(packages); index++)
            {
              # Only grab the product, not the fileset info
              if (packages[index] =~ '^#')
              {
                res = eregmatch(string:packages[index], pattern:'^#\\s([^\\s]+)\\s+([^\\s]+).*$');
                if (!empty_or_null(res))
                {
                  sw_inventory[res[1]] = make_array();
                  sw_inventory[res[1]]["version"] = res[2];
                  sw_inventory[res[1]]["method"] = "swlist";
                }
              }
            }
            break;
          case "pkg-list":
           packages = split(packages, sep:'\n', keep:FALSE);
           for (index = 1; index < max_index(packages); index++)
           {
             res = eregmatch(string:packages[index], pattern:'^([^\\s]+)\\s+([^\\s]+).*$');
             if (!empty_or_null(res))
             {
               sw_inventory[res[1]] = make_array();
               sw_inventory[res[1]]["version"] = res[2];
               sw_inventory[res[1]]["method"] = "Solaris11 pkg-list";
             }
           }
           break;
          default:
            continue;
        }
      }
    }
  }
  if (!empty_or_null(sw_inventory))
  {
    sw_inventory = make_nested_array("installed_software", sw_inventory);
    report_tag_internal(hostname:get_host_name(), tag:"software", value:sw_inventory);
  }
}

function enumerate_users()
{
  local_var username, kb_prefix, val, type, i, att, proto;
  local_var users = make_nested_array();

  local_var enum_types = make_list("LDAP", "WMI", "SMB");

  local_var user_types = make_array(
    # display, kb
    "Domain", "",
    "Local", "Local"
  );

  local_var attrs = make_nested_array(
    "LDAP", make_list(),
    "WMI", make_list(
      "SID",
      "Disabled",
      "Lockout",
      "PasswordChangeable"
    ),
    "SMB", make_list(
      "LogonTime",
      "LogoffTime",
      "PassLastSet",
      "KickoffTime",
      "PassCanChange",
      "PassMustChange",
      "ACB"
    )
  );

  foreach proto (enum_types)
  {
    # look at Domain and Local
    foreach type (keys(user_types))
    {
      if (empty_or_null(users[type])) users[type] = make_nested_array();
      # e.g. SMB/LocalUsers/ or SMB/Users
      kb_prefix = proto+"/"+user_types[type]+"Users/";

      local_var count = get_kb_item(kb_prefix+"count");
      if (isnull(count))
      {
        if (proto != "SMB") continue;
        # see if SMB null session was enumerated
        count = get_kb_item(kb_prefix+"NullSession/count");
        if (isnull(count)) continue;
        kb_prefix += "NullSession/";
      }

      local_var loop_prefix;
      # kb user index starts at 1
      for (i = 1; i <= count; i++)
      {
        loop_prefix = kb_prefix+i;
        username = get_kb_item(loop_prefix);
        if (isnull(username)) continue;

        # set user attributes
        if (empty_or_null(users[type][username])) users[type][username] = make_nested_array();
        loop_prefix += "/Info/";

        foreach att (attrs[proto])
        {
          val = get_kb_item(loop_prefix+att);
          if (!isnull(val))
            users[type][username][att] = val;
        }
      }
    }
  }

  # clean up empty lists/arrays
  foreach type (keys(users))
  {
    if (empty_or_null(users[type])) delete_element(idx:type, var:users);
  }

  if (!empty_or_null(users))
  {
    users = make_nested_array("Users", users);
    report_tag_internal(hostname:get_host_name(), tag:"users", value:users);
  }
}

function enumerate_groups()
{
  local_var protos, proto;
  local_var groups = make_nested_array();
  local_var group_count, user_count, group_attrs, user_attr, att;
  local_var group_name, username, loop_prefix, user_loop_prefix;
  local_var kb_prefix, i, k, type, members, admin;
  local_var types = make_array(
    'Domain', '',
    'Local', 'Local'
  );

  protos = make_nested_array(
   'LDAP', make_list(),
   'WMI', make_list('Hostname', 'SID')
  );

  foreach type (keys(types))
  {
    if (empty_or_null(groups[type])) groups[type] = make_nested_array();

    foreach proto (keys(protos))
    {
      kb_prefix = proto+'/'+types[type]+'Groups/';
      group_count = get_kb_item(kb_prefix+'count');
      if (isnull(group_count)) continue;

      for (i = 1; i <= group_count; i++)
      {
        loop_prefix = kb_prefix+i;
        group_name = get_kb_item(loop_prefix);
        if (isnull(group_name)) continue;
        groups[type][group_name] = make_nested_array();
        loop_prefix += '/Info/';

        group_attrs = protos[proto]; # a list
        foreach att (group_attrs)
        {
          groups[type][group_name][att] = get_kb_item(loop_prefix+att);
        }

        # enumerate group users
        user_count = get_kb_item(loop_prefix+'Members/count');
        if (isnull(user_count)) continue;
        members = make_list();
        for (k = 1; k <= user_count; k++)
        {
          user_loop_prefix = loop_prefix+'Members/'+k;
          username = get_kb_item(user_loop_prefix);
          if (isnull(username)) continue;
          members = make_list(username, members);
        }
        if (len(members) > 0)
          groups[type][group_name]['Members'] = members;
      }
    }
  }
  # Admins
  protos = make_nested_array(
    'LDAP', make_list('Domain', 'Domain Admins'),
    'SSH', make_list('Local', 'Admins')
  );

  local_var admins, context;
  foreach proto (keys(protos))
  {
    context = protos[proto][0]; # domain/local
    admins = get_kb_list(proto+"/"+context+"Admins/Members/*");
    if(!isnull(admins))
    {
      group_name = protos[proto][1];
      if (empty_or_null(groups[context]))
        groups[context] = make_nested_array();
      local_var admin_list = make_array();
      foreach admin (keys(admins))
      {
        admin_list[admins[admin]] = 1;
      }
      groups[context][group_name] = keys(admin_list);
    }
  }

  # clean up empty lists/arrays
  foreach type (keys(groups))
  {
    if (empty_or_null(groups[type])) delete_element(idx:type, var:groups);
  }

  if (!empty_or_null(groups))
  {
    groups = make_nested_array("Groups", groups);
    report_tag_internal(hostname:get_host_name(), tag:"groups", value:groups);
  }
}

function enumerate_misc()
{
  local_var att, attrs, type, key;
  local_var misc = make_nested_array();

  local_var last_user_login = get_kb_item("SMB/last_user_login");
  if (!isnull(last_user_login))
    misc['Last User Login'] = last_user_login;

  local_var enum_types = make_nested_array(
    "SSH", make_array(
      "PwNeverExpires", "PwNeverExpires"
    ),
    "SMB", make_array(
      "AutoDisabled",  "Auto-disabled",
      "PwCantChange",  "PwCantChange",
      "Disabled",      "Disabled",
      "NeverChangedPw","NeverChangedPw",
      "NeverLoggedOn", "NeverLoggedOn",
      "PwNeverExpires","PwNeverExpires"
    )
  );

  foreach type (keys(enum_types))
  {
    attrs = enum_types[type];
    foreach att (keys(attrs))
    {
      local_var kb_list = get_kb_list(type+"/LocalUsers/"+att+"/*");
      local_var disp = attrs[att];
      if (!isnull(kb_list))
      {
        misc[disp] = make_list();
        foreach key (keys(kb_list))
        {
          misc[disp] = make_list(misc[disp], kb_list[key]);
        }
      }
    }
  }

  if (!empty_or_null(misc))
  {
    misc = make_nested_array("Misc", misc);
    report_tag_internal(hostname:get_host_name(), tag:"misc", value:misc);
  }
}

enumerate_interfaces();
enumerate_software();
enumerate_users();
enumerate_groups();
enumerate_misc();
