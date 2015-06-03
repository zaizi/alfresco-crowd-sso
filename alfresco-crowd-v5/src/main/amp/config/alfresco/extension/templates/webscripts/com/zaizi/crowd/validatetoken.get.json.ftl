<#escape x as jsonUtils.encodeJSONString(x)>
{
   "valid": "${valid}"
   <#if alf_token??>
   , "ticket": "${alf_token}",
     "user": "${user}"
   </#if>
}
</#escape>