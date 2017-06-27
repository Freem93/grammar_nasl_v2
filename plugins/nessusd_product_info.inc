
include("agent.inc");

##
#  Returns nasl_environment() array by default.
#  Supports returning an optional element by passing key:
#    build, level, product, version, internal_build, os, is_cmdline, etc.
#
##
function nessusd_env()
{
  local_var env, key;

  if(defined_func("nasl_environment"))
  {
    env = nasl_environment();

   # use passed argument for key
   key = _FCT_ANON_ARGS[0];
   if(!isnull(key) && !isnull(env[key]))
   {
     return env[key];
   }
   else
     return env;
  }

  # older nussusd
  return NULL;
}

##
#
# Wrapper to pull 'product' from nasl_environment
#
# @return one of:
#   PRODUCT_WIN_AGENT     - Windows agent (1)
#   PRODUCT_UNIX_AGENT    - Unix agent (2)
#   PRODUCT_NESSUSD       - Normal nessusd (0)
#   PRODUCT_NESSUSD_NSX   - Nessusd in NSX environment (3)
#   NULL - nessusd product undetermined
#
##
function nessusd_product()
{
  return nessusd_env('product');
}

##
# Wrapper to pull 'os' from nasl_environment
##
function nessusd_os()
{
  return nessusd_env('os');
}

##
#
##
function nessusd_is()
{
  local_var prod, target;

  target = _FCT_ANON_ARGS[0];
  if(isnull(target)) return FALSE;

  prod = nessusd_product();

  return (prod == target);
}

##
#
##
function nessusd_is_win_agent()
{
  return nessusd_is(PRODUCT_WIN_AGENT);
}

##
#
##
function nessusd_is_mac_agent()
{
  return nessusd_is(PRODUCT_MAC_AGENT);
}

##
#
##
function nessusd_is_unix_agent()
{
  return nessusd_is(PRODUCT_UNIX_AGENT);
}

##
#
##
function nessusd_is_nsx()
{
  return nessusd_is(PRODUCT_NESSUSD_NSX);
}


##
# Is nessusd run in agent mode?
##
function nessusd_is_agent()
{
  local_var prod;

  prod = nessusd_product();

  if( !isnull(prod) &&
      (prod == PRODUCT_WIN_AGENT
        || prod == PRODUCT_UNIX_AGENT
        || prod == PRODUCT_MAC_AGENT
        # || prod == PRODUCT_NESSUSD_NSX  # Nessusd in NSX is an agent?
      )
   ) return TRUE;

  return FALSE;
}

##
# Is nessusd used in a local scan environment?
# @todo add in local_host() to the check
##
function nessusd_is_local()
{
  local_var prod;

  prod = nessusd_product();

  if( !isnull(prod) &&
     ( prod == PRODUCT_WIN_AGENT
     || prod == PRODUCT_UNIX_AGENT
     || prod == PRODUCT_MAC_AGENT
     || prod == PRODUCT_NESSUSD_NSX
     || islocalhost()
    )
   ) return TRUE;

  return FALSE;
}
