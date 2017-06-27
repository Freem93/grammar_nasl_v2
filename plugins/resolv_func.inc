#TRUSTED 6c8de48805b402f4d654974e9bf8fecedb4a2df04602178e4e4ac93db00385f3abf7d79f0cdd6dbdf4979fa2465dcec3946eb70c59667f889870346b1dc5e9d6d87c7b897fa45323e8082d08eb22ed1f4420f7ccdcab87a1ebece13a7cd3dde3a3ac0933d7151a7dfb7a230cd71c5185d8993ad60df42c63d140353e8e1edf33c33511c3448eb65401416f86be3e53e21773b3c9c949448adeda021114ce63eb6732cab754b9a4a046fe0109ceaec827e5862692ff7bd2fe4afdfc7d4eec1f7675dfcb53db794fe3913efed11cc23c579eecc0415a6b44305dcf5304dc7490726dbcb35c9030bd563b2c2b83dd1afa19c4f7c0a199408565b5569a810d1f18cfef355b71eb52c03b01920e131a3ccabda8edf42ba79654067900db7fef2543d889247fb016fc895736837b291057dc7cb7f517172120da6447fe5fd28114b6c938b3d3e44c24dbfc652705e11659f95b5234492857004af4f61fcc3b3a61494d3d25f0e2209cadc38e6118f694a536cf65c354d2a759dd00b2ccc8553f937d3e43a5a62ed49ff46c702d9baea69976b53fd22c2b7b97fab1ac4eaeceaa565d507d4127ae40cfb7d878154130cd6f4cf6ce4087da722529c9daae01044e39458d99d258a451ee487f52dcfff1199b68db3775472bcf999796ddb55e37acf2929c795e5f706d31de3e9bf88eca45084d862b206b5bc1dab22cbbbb6c72c934149c
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# resolv_func.inc
#
# Revision: 1.8
#

include ("spad_log_func.inc");
include ("obj.inc");

function is_host_ip(name)
{
 if (":" >< name || ereg(string:name, pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$") )
   return TRUE;

 return FALSE;
}


function fqdn_resolv(name, ipv6, fqdn)
{
  local_var len, resolv, msg, log_name;

  # Check to make sure we are not trying to resolve an IP
  if ( is_host_ip(name:name) ) return make_list(name);

  # Adds a "." at the end of the name to make sure it is a FQDN
  if ( fqdn )
  {
   len = strlen(name);
   if ( len > 0 && name[len-1] != '.' )
     name = name + ".";
  }

  resolv = resolv(name:name, ipv6:ipv6);

  if(get_kb_item("global_settings/enable_plugin_debugging"))
  {
    msg = '[fqdn_resolv] Resolving the IP for the following FQDN :\n' +
          '\tName : ' + name + '\n' +
          '\tIP : ' + obj_rep(resolv) + '\n';

    log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
    spad_log(message:msg,name:log_name);
  }

  return resolv;
}

function cmp_addr_v(a, b)
{
  local_var am, bm, ai, bi, msg, log_name;

  am = max_index(a);
  bm = max_index(b);

  for (ai = 0; ai < am; ai ++)
  {
    for (bi = 0; bi < bm; bi ++)
    {
      if(get_kb_item("global_settings/enable_plugin_debugging"))
      {
        msg = '[cmp_addr_v] Comparing the following IPs :\n' +
              '\tIP 1 : ' + a[ai] + '\n' +
              '\tIP 2 : ' + b[bi] + '\n';

        log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
        spad_log(message:msg,name:log_name);
      }

      if (a[ai] == b[bi])
        return 1;
    }
  }
  return 0;
}

global_var _target_ip_resolv, _target_name_resolv;

# If b=NULL, compare a with the target
function is_same_host(a, b, fqdn)
{
  local_var v1, v2, b1, b2, ipv6, msg, log_name;

  if(get_kb_item("global_settings/enable_plugin_debugging"))
  {
    msg = '[is_same_host] Comparing the following two hosts :\n' +
          '\tHost 1 : ' + a + '\n' +
          '\tHost 2 : ' + b + '\n';

    log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
    spad_log(message:msg,name:log_name);
  }

  if (a == b) return 1;

  if (isnull(b))
  {
    if (isnull(a))
    {
      display("ERR: is_same_host: missing arguments 'a' & 'b'\n");
      return NULL;
    }
    b1 = get_host_ip();
    b2 = get_host_name();

    if(get_kb_item("global_settings/enable_plugin_debugging"))
    {
      msg = 'We got the following when getting the host information for comparison :\n' +
            '\tHost IP : ' + b1 + '\n' +
            '\tHost Name : ' + b2 + '\n';

      log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
      spad_log(message:msg,name:log_name);
    }

    if (a == b1 || tolower(a) == tolower(b2)) return 1;
    if (! defined_func("resolv")) return 0;

    if (isnull(_target_ip_resolv))
    {
      _target_ip_resolv = fqdn_resolv(name: b1, ipv6: TARGET_IS_IPV6, fqdn: FALSE);
      if (isnull(_target_ip_resolv)) return NULL;
    }
    v2 = fqdn_resolv(name: a, ipv6: TARGET_IS_IPV6, fqdn: fqdn);
    if (isnull(v2)) return NULL;
    if (cmp_addr_v(a: _target_ip_resolv, b: v2)) return 1;

    if (b1 != b2)
    {
      if (isnull(_target_name_resolv))
      {
        _target_name_resolv = fqdn_resolv(name: b2, ipv6: TARGET_IS_IPV6, fqdn: fqdn);
        if (isnull(_target_name_resolv)) return NULL;
      }
      if (cmp_addr_v(a: _target_name_resolv, b: v2)) return 1;
    }

    return 0;
  }

  if (! defined_func("resolv")) return 0;

  for (ipv6 = 0; ipv6 <= 1; ipv6 ++)
  {
    v1 = fqdn_resolv(name: a, ipv6: ipv6, fqdn: fqdn);
    if (isnull(v1)) continue;
    v2 = fqdn_resolv(name: b, ipv6: ipv6, fqdn: fqdn);
    if (isnull(v2)) continue;

    if (cmp_addr_v(a: v1, b: v2)) return 1;
  }

  return 0;
}
