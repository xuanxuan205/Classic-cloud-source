package com.jdy.cloud.security;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * IronWall v1.28.11: 引擎中间件 JSON 双写回归防护。
 */
class MinimalErrorReportValveTest {

    static class ExposedValve extends MinimalErrorReportValve {
        void reportPublic(Request request, Response response, Throwable throwable) {
            report(request, response, throwable);
        }
    }

    @Test
    void committedResponseMustNotBeWrittenAgain() throws Exception {
        ExposedValve valve = new ExposedValve();
        Request request = mock(Request.class);
        Response response = mock(Response.class);
        when(response.isCommitted()).thenReturn(true);
        valve.reportPublic(request, response, new RuntimeException("x"));
        verify(response, never()).getWriter();
        verify(response, never()).setContentType(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void responseBodyAlreadyWrittenMustNotBeDoubled() throws Exception {
        ExposedValve valve = new ExposedValve();
        Request request = mock(Request.class);
        Response response = mock(Response.class);
        when(response.isCommitted()).thenReturn(false);
        when(response.getStatus()).thenReturn(429);
        when(response.getContentWritten()).thenReturn(128L);
        valve.reportPublic(request, response, new RuntimeException("x"));
        verify(response, never()).getWriter();
    }

    @Test
    void alreadyReportedResponseMustNotBeWrittenAgain() throws Exception {
        ExposedValve valve = new ExposedValve();
        Request request = mock(Request.class);
        Response response = mock(Response.class);
        when(response.isCommitted()).thenReturn(false);
        when(response.getStatus()).thenReturn(429);
        when(response.getContentWritten()).thenReturn(0L);
        when(response.setErrorReported()).thenReturn(false);
        valve.reportPublic(request, response, new RuntimeException("x"));
        verify(response, never()).getWriter();
    }

    @Test
    void untouchedErrorResponseGetsMinimalJson() throws Exception {
        ExposedValve valve = new ExposedValve();
        Request request = mock(Request.class);
        Response response = mock(Response.class);
        when(response.isCommitted()).thenReturn(false);
        when(response.getStatus()).thenReturn(400);
        when(response.getContentWritten()).thenReturn(0L);
        when(response.setErrorReported()).thenReturn(true);
        valve.reportPublic(request, response, new RuntimeException("x"));
        verify(response).getWriter();
    }
}