using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using System.Diagnostics;

namespace WebAppTemplate.Filters
{
    public class StopwatchFilterAttribute : ActionFilterAttribute
    {
        private const string StopwatchKey = "StopwatchFilter.Value";

        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            actionContext.Request.Properties[StopwatchKey] = Stopwatch.StartNew();
            base.OnActionExecuting(actionContext);
        }

        public override void OnActionExecuted(HttpActionExecutedContext actionExecutedContext)
        {
            Stopwatch stopwatch = (Stopwatch)actionExecutedContext.Request.Properties[StopwatchKey];
            if (actionExecutedContext.Response != null)
                actionExecutedContext.Response.Headers.Add("X-Runtime", stopwatch.Elapsed.TotalMilliseconds.ToString());
            base.OnActionExecuted(actionExecutedContext);
        }

    }
}