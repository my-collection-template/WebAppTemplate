using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;
using WebAppTemplate.Infrastructure;

namespace WebAppTemplate.Filters
{
    public class AppExceptionFilter : ExceptionFilterAttribute
    {
        public override void OnException(HttpActionExecutedContext context)
        {
            string refCode = ", reference:" + DateTime.Now.Ticks;
            TracingSystem.TraceException(context.ActionContext.Request.RequestUri.AbsolutePath + refCode, context.Exception);
            throw new HttpResponseException(context.Request.CreateErrorResponse(HttpStatusCode.InternalServerError, "an error has occurred" + refCode));
        }
    }
}