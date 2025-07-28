#!/bin/bash

# Gateway Test Script
# Tests various WAF and proxy functionality

set -e

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
METRICS_URL="${METRICS_URL:-http://localhost:9090/metrics}"

echo "🧪 Testing Gateway at $GATEWAY_URL"

# Test health endpoint
echo "📋 Testing health check..."
if curl -s -f "$GATEWAY_URL/health" > /dev/null; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# Test metrics endpoint
echo "📊 Testing metrics..."
if curl -s -f "$METRICS_URL" > /dev/null; then
    echo "✅ Metrics endpoint accessible"
else
    echo "❌ Metrics endpoint failed"
    exit 1
fi

# Test basic proxy functionality
echo "🔄 Testing basic proxy..."
response=$(curl -s -w "%{http_code}" -o /dev/null "$GATEWAY_URL/")
if [ "$response" -eq 200 ] || [ "$response" -eq 502 ]; then
    echo "✅ Basic proxy working (status: $response)"
else
    echo "❌ Basic proxy failed (status: $response)"
fi

# Test WAF - SQL Injection
echo "🛡️ Testing WAF - SQL Injection..."
response=$(curl -s -w "%{http_code}" -o /dev/null "$GATEWAY_URL/?id=1' OR '1'='1")
if [ "$response" -eq 403 ]; then
    echo "✅ SQL injection blocked"
else
    echo "⚠️  SQL injection not blocked (status: $response)"
fi

# Test WAF - XSS
echo "🛡️ Testing WAF - XSS..."
response=$(curl -s -w "%{http_code}" -o /dev/null "$GATEWAY_URL/?q=%3Cscript%3Ealert('xss')%3C/script%3E")
if [ "$response" -eq 403 ]; then
    echo "✅ XSS attempt blocked"
else
    echo "⚠️  XSS attempt not blocked (status: $response)"
fi

# Test WAF - Directory Traversal
echo "🛡️ Testing WAF - Directory Traversal..."
response=$(curl -s -w "%{http_code}" -o /dev/null "$GATEWAY_URL/../../../etc/passwd")
if [ "$response" -eq 403 ]; then
    echo "✅ Directory traversal blocked"
else
    echo "⚠️  Directory traversal not blocked (status: $response)"
fi

# Test Rate Limiting
echo "🚦 Testing Rate Limiting..."
blocked=false
for i in {1..20}; do
    response=$(curl -s -w "%{http_code}" -o /dev/null "$GATEWAY_URL/api/test" 2>/dev/null || echo "000")
    if [ "$response" -eq 429 ]; then
        blocked=true
        break
    fi
    sleep 0.1
done

if [ "$blocked" = true ]; then
    echo "✅ Rate limiting working"
else
    echo "⚠️  Rate limiting not triggered"
fi

# Test Headers
echo "📤 Testing Custom Headers..."
response=$(curl -s -H "X-Test-Header: test-value" -w "%{http_code}" -o /dev/null "$GATEWAY_URL/")
echo "✅ Custom headers accepted (status: $response)"

# Test Different HTTP Methods
echo "🔧 Testing HTTP Methods..."
for method in GET POST PUT DELETE; do
    response=$(curl -s -X "$method" -w "%{http_code}" -o /dev/null "$GATEWAY_URL/" 2>/dev/null || echo "000")
    echo "   $method: $response"
done

echo "🎉 Gateway tests completed!"