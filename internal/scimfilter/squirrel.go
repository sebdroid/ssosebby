package scimfilter

import (
	"fmt"
	"strings"

	sq "github.com/Masterminds/squirrel"
	filter "github.com/scim2/filter-parser"
)

// ParsedFilter contains the parsed SCIM filter as squirrel conditions
type ParsedFilter struct {
	Where sq.Sqlizer
}

// ParseToSquirrel parses a SCIM filter string and returns squirrel conditions.
// Returns nil Where if the filter is empty.
func ParseToSquirrel(filterStr string, resourceType ResourceType) (*ParsedFilter, error) {
	if filterStr == "" {
		return &ParsedFilter{Where: nil}, nil
	}

	// Pre-process to handle unquoted boolean values
	filterStr = normalizeFilterBooleans(filterStr)

	parser := filter.NewParser(strings.NewReader(filterStr))
	expr, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("parse filter: %w", err)
	}

	converter := &squirrelConverter{resourceType: resourceType}
	where, err := converter.convert(expr)
	if err != nil {
		return nil, fmt.Errorf("convert filter: %w", err)
	}

	return &ParsedFilter{Where: where}, nil
}

type squirrelConverter struct {
	resourceType ResourceType
}

func (c *squirrelConverter) convert(expr filter.Expression) (sq.Sqlizer, error) {
	switch e := expr.(type) {
	case filter.AttributeExpression:
		return c.convertAttribute(e)
	case filter.BinaryExpression:
		return c.convertBinary(e)
	case filter.UnaryExpression:
		return c.convertUnary(e)
	case filter.ValuePath:
		return c.convertValuePath(e)
	default:
		return nil, fmt.Errorf("unsupported expression type: %T", expr)
	}
}

func (c *squirrelConverter) convertAttribute(expr filter.AttributeExpression) (sq.Sqlizer, error) {
	attrName := strings.ToLower(expr.AttributePath.AttributeName)
	subAttr := expr.AttributePath.SubAttribute // preserve case for JSONB key matching

	// Validate attribute names to prevent SQL injection
	if !isValidAttributeName(attrName) {
		return nil, fmt.Errorf("invalid attribute name: %q", attrName)
	}
	if subAttr != "" && !isValidAttributeName(subAttr) {
		return nil, fmt.Errorf("invalid sub-attribute name: %q", subAttr)
	}

	// Check if this is a boolean attribute
	isBooleanAttr := c.isBooleanAttribute(attrName)

	// Get the SQL column for this attribute
	col, err := c.attributeToColumn(attrName, subAttr)
	if err != nil {
		return nil, err
	}

	// Handle presence operator (no value)
	if expr.CompareOperator == filter.PR {
		return sq.And{
			sq.NotEq{col: nil},
			sq.NotEq{col: ""},
		}, nil
	}

	// Get the comparison value
	value := expr.CompareValue

	// Handle boolean attributes specially
	if isBooleanAttr {
		boolVal, err := parseBoolValue(value)
		if err != nil {
			return nil, fmt.Errorf("invalid boolean value for %s: %w", attrName, err)
		}
		switch expr.CompareOperator {
		case filter.EQ:
			return sq.Eq{col: boolVal}, nil
		case filter.NE:
			return sq.NotEq{col: boolVal}, nil
		default:
			return nil, fmt.Errorf("operator %v not supported for boolean attribute %s", expr.CompareOperator, attrName)
		}
	}

	// Convert operator and build condition
	switch expr.CompareOperator {
	case filter.EQ:
		return sq.Eq{col: value}, nil
	case filter.NE:
		return sq.NotEq{col: value}, nil
	case filter.CO:
		return sq.ILike{col: "%" + escapePattern(value) + "%"}, nil
	case filter.SW:
		return sq.ILike{col: escapePattern(value) + "%"}, nil
	case filter.EW:
		return sq.ILike{col: "%" + escapePattern(value)}, nil
	case filter.GT:
		return sq.Gt{col: value}, nil
	case filter.GE:
		return sq.GtOrEq{col: value}, nil
	case filter.LT:
		return sq.Lt{col: value}, nil
	case filter.LE:
		return sq.LtOrEq{col: value}, nil
	default:
		return nil, fmt.Errorf("unsupported operator: %v", expr.CompareOperator)
	}
}

func (c *squirrelConverter) convertBinary(expr filter.BinaryExpression) (sq.Sqlizer, error) {
	left, err := c.convert(expr.X)
	if err != nil {
		return nil, err
	}

	right, err := c.convert(expr.Y)
	if err != nil {
		return nil, err
	}

	switch expr.CompareOperator {
	case filter.AND:
		return sq.And{left, right}, nil
	case filter.OR:
		return sq.Or{left, right}, nil
	default:
		return nil, fmt.Errorf("unsupported binary operator: %v", expr.CompareOperator)
	}
}

func (c *squirrelConverter) convertUnary(expr filter.UnaryExpression) (sq.Sqlizer, error) {
	child, err := c.convert(expr.X)
	if err != nil {
		return nil, err
	}

	if expr.CompareOperator == filter.NOT {
		// Use sq.Expr to wrap with NOT
		childSQL, childArgs, err := child.ToSql()
		if err != nil {
			return nil, err
		}
		return sq.Expr("NOT ("+childSQL+")", childArgs...), nil
	}

	return nil, fmt.Errorf("unsupported unary operator: %v", expr.CompareOperator)
}

func (c *squirrelConverter) convertValuePath(expr filter.ValuePath) (sq.Sqlizer, error) {
	attrName := strings.ToLower(expr.AttributeName)

	if expr.ValueExpression == nil {
		col, err := c.attributeToColumn(attrName, "")
		if err != nil {
			return nil, err
		}
		return sq.NotEq{col: nil}, nil
	}

	return nil, fmt.Errorf("complex value paths not yet supported: %s[...]", attrName)
}

func (c *squirrelConverter) isBooleanAttribute(attrName string) bool {
	if c.resourceType == ResourceTypeUser {
		return attrName == "active"
	}
	return false
}

func (c *squirrelConverter) attributeToColumn(attrName, subAttr string) (string, error) {
	switch c.resourceType {
	case ResourceTypeUser:
		return c.userAttributeToColumn(attrName, subAttr)
	case ResourceTypeGroup:
		return c.groupAttributeToColumn(attrName, subAttr)
	default:
		return "", fmt.Errorf("unknown resource type")
	}
}

func (c *squirrelConverter) userAttributeToColumn(attrName, subAttr string) (string, error) {
	switch attrName {
	case "username", "email":
		return "email", nil
	case "id":
		return "id::text", nil
	case "externalid":
		return "(attributes->>'externalId')", nil
	case "active":
		return "(attributes->>'active')::boolean", nil
	case "name":
		if subAttr != "" {
			return fmt.Sprintf("(attributes->'name'->>'%s')", escapeJsonbKey(subAttr)), nil
		}
		return "(attributes->>'name')", nil
	case "displayname":
		return "(attributes->>'displayName')", nil
	case "title":
		return "(attributes->>'title')", nil
	case "usertype":
		return "(attributes->>'userType')", nil
	case "preferredlanguage":
		return "(attributes->>'preferredLanguage')", nil
	case "locale":
		return "(attributes->>'locale')", nil
	case "timezone":
		return "(attributes->>'timezone')", nil
	case "emails":
		if subAttr == "value" {
			return "email", nil
		}
		return "(attributes->>'emails')", nil
	default:
		if subAttr != "" {
			return fmt.Sprintf("(attributes->'%s'->>'%s')", escapeJsonbKey(attrName), escapeJsonbKey(subAttr)), nil
		}
		return fmt.Sprintf("(attributes->>'%s')", escapeJsonbKey(attrName)), nil
	}
}

func (c *squirrelConverter) groupAttributeToColumn(attrName, subAttr string) (string, error) {
	switch attrName {
	case "id":
		return "id::text", nil
	case "displayname":
		return "display_name", nil
	case "externalid":
		return "(attributes->>'externalId')", nil
	default:
		if subAttr != "" {
			return fmt.Sprintf("(attributes->'%s'->>'%s')", escapeJsonbKey(attrName), escapeJsonbKey(subAttr)), nil
		}
		return fmt.Sprintf("(attributes->>'%s')", escapeJsonbKey(attrName)), nil
	}
}
