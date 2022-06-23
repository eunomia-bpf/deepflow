package clickhouse

import (
	"errors"
	"fmt"
	"net"
	"server/querier/common"
	"server/querier/engine/clickhouse/metrics"
	"server/querier/engine/clickhouse/tag"
	"server/querier/engine/clickhouse/view"
	"strconv"
	"strings"
)

const (
	TAG_FUNCTION_NODE_TYPE                  = "node_type"
	TAG_FUNCTION_ICON_ID                    = "icon_id"
	TAG_FUNCTION_MASK                       = "mask"
	TAG_FUNCTION_TIME                       = "time"
	TAG_FUNCTION_TO_UNIX_TIMESTAMP_64_MICRO = "toUnixTimestamp64Micro"
	TAG_FUNCTION_TO_UNIX_TIMESTAMP          = "toUnixTimestamp"
	TAG_FUNCTION_TO_STRING                  = "toString"
	TAG_FUNCTION_IF                         = "if"
	TAG_FUNCTION_UNIQ                       = "uniq"
	TAG_FUNCTION_ANY                        = "any"
	TAG_FUNCTION_TOPK                       = "topK"
	TAG_FUNCTION_NEW_TAG                    = "newTag"
)

var TAG_FUNCTIONS = []string{
	TAG_FUNCTION_NODE_TYPE, TAG_FUNCTION_ICON_ID, TAG_FUNCTION_MASK, TAG_FUNCTION_TIME,
	TAG_FUNCTION_TO_UNIX_TIMESTAMP_64_MICRO, TAG_FUNCTION_TO_STRING, TAG_FUNCTION_IF,
	TAG_FUNCTION_UNIQ, TAG_FUNCTION_ANY, TAG_FUNCTION_TOPK, TAG_FUNCTION_TO_UNIX_TIMESTAMP,
	TAG_FUNCTION_NEW_TAG,
}

type Function interface {
	Statement
	Trans(m *view.Model) view.Node
	SetAlias(alias string)
}

func GetTagFunction(name string, args []string, alias, db, table string) (Statement, error) {
	if !common.IsValueInSliceString(name, TAG_FUNCTIONS) {
		return nil, nil
	}
	switch name {
	case "time":
		time := Time{Args: args, Alias: alias}
		return &time, nil
	default:
		tagFunction := TagFunction{Name: name, Args: args, Alias: alias, DB: db, Table: table}
		err := tagFunction.Check()
		return &tagFunction, err
	}
}

func GetAggFunc(name string, args []string, alias string, db string, table string) (Statement, int, error) {
	var levelFlag int
	field := args[0]
	field = strings.Trim(field, "`")
	metricStruct, ok := metrics.GetMetrics(field, db, table)
	if !ok {
		return nil, 0, nil
	}
	if _, ok := metrics.METRICS_FUNCTIONS_MAP[name]; !ok {
		return nil, 0, nil
	}
	// 判断算子是否支持单层
	unlayFuns := metrics.METRICS_TYPE_UNLAY_FUNCTIONS[metricStruct.Type]
	if common.IsValueInSliceString(name, unlayFuns) {
		levelFlag = view.MODEL_METRICS_LEVEL_FLAG_UNLAY
	} else {
		levelFlag = view.MODEL_METRICS_LEVEL_FLAG_LAYERED
	}
	return &AggFunction{
		Metrics: metricStruct,
		Name:    name,
		Args:    args,
		Alias:   alias,
	}, levelFlag, nil
	return nil, levelFlag, nil
}

func GetBinaryFunc(name string, args []Function) (*BinaryFunction, error) {
	return &BinaryFunction{
		Name:      name,
		Functions: args,
	}, nil
}

func GetFieldFunc(name string) (FieldFunction, error) {
	switch strings.ToLower(name) {
	case "time_interval":
		return &TimeIntervalField{}, nil
	}
	return nil, nil
}

func GetDefaultAlias(name string, args []string) string {
	alias := name
	for _, arg := range args {
		alias = fmt.Sprintf("%s_%s", alias, strings.ToLower(arg))
	}
	return alias
}

type BinaryFunction struct {
	Name      string
	Functions []Function
	Alias     string
}

func (f *BinaryFunction) Trans(m *view.Model) view.Node {
	var fields []view.Node
	for _, field := range f.Functions {
		fieldFunc := field.Trans(m)
		fields = append(fields, fieldFunc)
	}
	function := view.GetFunc(f.Name)
	function.SetFields(fields)
	function.SetFlag(view.METRICS_FLAG_OUTER)
	function.SetTime(m.Time)
	function.Init()
	return function
}

func (f *BinaryFunction) Format(m *view.Model) {
	function := f.Trans(m)
	if aggfunc, ok := function.(view.Function); ok {
		aggfunc.SetAlias(f.Alias, false)
		m.AddTag(aggfunc)
	} else {
		m.AddTag(function)
	}
}

func (f *BinaryFunction) SetAlias(alias string) {
	f.Alias = alias
}

type AggFunction struct {
	// 指标量内容
	Metrics *metrics.Metrics
	// 解析获得的参数
	Name  string
	Args  []string
	Alias string
}

func (f *AggFunction) SetAlias(alias string) {
	f.Alias = alias
}

func (f *AggFunction) FormatInnerTag(m *view.Model) (innerAlias string) {
	switch f.Metrics.Type {
	case metrics.METRICS_TYPE_COUNTER, metrics.METRICS_TYPE_GAUGE:
		// 计数类和油标类，内层结构为sum
		// 内层算子使用默认alias
		innerFunction := view.DefaultFunction{
			Name:   view.FUNCTION_SUM,
			Fields: []view.Node{&view.Field{Value: f.Metrics.DBField}},
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metrics.METRICS_TYPE_DELAY:
		// 时延类，内层结构为groupArray，忽略0值
		innerFunction := view.DefaultFunction{
			Name:       view.FUNCTION_GROUP_ARRAY,
			Fields:     []view.Node{&view.Field{Value: f.Metrics.DBField}},
			IgnoreZero: true,
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metrics.METRICS_TYPE_PERCENTAGE, metrics.METRICS_TYPE_QUOTIENT:
		// 比例类和商值类，内层结构为sum(x)/sum(y)
		divFields := strings.Split(f.Metrics.DBField, "/")
		divField_0 := view.DefaultFunction{
			Name:   view.FUNCTION_SUM,
			Fields: []view.Node{&view.Field{Value: divFields[0]}},
		}
		divField_1 := view.DefaultFunction{
			Name:   view.FUNCTION_SUM,
			Fields: []view.Node{&view.Field{Value: divFields[1]}},
		}
		innerFunction := view.DivFunction{
			DefaultFunction: view.DefaultFunction{
				Name:   view.FUNCTION_DIV,
				Fields: []view.Node{&divField_0, &divField_1},
			},
		}
		innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	case metrics.METRICS_TYPE_TAG:
		innerAlias := fmt.Sprintf("_%s", f.Alias)
		innerFunction := view.DefaultFunction{
			Name:      view.FUNCTION_GROUP_ARRAY,
			Fields:    []view.Node{&view.Field{Value: f.Metrics.DBField}},
			Condition: f.Metrics.Condition,
			Alias:     innerAlias,
		}
		//innerAlias = innerFunction.SetAlias("", true)
		innerFunction.SetFlag(view.METRICS_FLAG_INNER)
		innerFunction.Init()
		m.AddTag(&innerFunction)
		return innerAlias
	}
	return ""
}

func (f *AggFunction) Trans(m *view.Model) view.Node {
	outFunc := view.GetFunc(f.Name)
	if len(f.Args) > 1 {
		outFunc.SetArgs(f.Args[1:])
	}
	if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED {
		innerAlias := f.FormatInnerTag(m)
		switch f.Metrics.Type {
		case metrics.METRICS_TYPE_COUNTER, metrics.METRICS_TYPE_GAUGE:
			// 计数类和油标类，null需要补成0
			outFunc.SetFillNullAsZero(true)
		case metrics.METRICS_TYPE_DELAY:
			// 时延类和商值类，忽略0值
			outFunc.SetIsGroupArray(true)
			outFunc.SetIgnoreZero(true)
		case metrics.METRICS_TYPE_QUOTIENT:
			outFunc.SetIgnoreZero(true)
		case metrics.METRICS_TYPE_PERCENTAGE:
			// 比例类，null需要补成0
			outFunc.SetFillNullAsZero(true)
			outFunc.SetMath("*100")
		case metrics.METRICS_TYPE_TAG:
			outFunc.SetIsGroupArray(true)
		}
		outFunc.SetFields([]view.Node{&view.Field{Value: innerAlias}})
	} else if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_UNLAY {
		switch f.Metrics.Type {
		case metrics.METRICS_TYPE_COUNTER:
			outFunc.SetFillNullAsZero(true)
		case metrics.METRICS_TYPE_DELAY:
			outFunc.SetIgnoreZero(true)
		case metrics.METRICS_TYPE_PERCENTAGE:
			outFunc.SetFillNullAsZero(true)
		case metrics.METRICS_TYPE_TAG:
			outFunc.SetCondition(f.Metrics.Condition)
		}
		outFunc.SetFields([]view.Node{&view.Field{Value: f.Metrics.DBField}})
	}
	outFunc.SetFlag(view.METRICS_FLAG_OUTER)
	outFunc.SetTime(m.Time)
	outFunc.Init()
	return outFunc
}

func (f *AggFunction) Format(m *view.Model) {
	outFunc := f.Trans(m)
	if f.Alias != "" {
		outFunc.(view.Function).SetAlias(f.Alias, false)
	}
	m.AddTag(outFunc)
}

type Field struct {
	Value string
}

func (f *Field) Trans(m *view.Model) view.Node {
	return &view.Field{Value: f.Value}
}

func (f *Field) Format(m *view.Model) {}

func (f *Field) SetAlias(alias string) {}

type FieldFunction interface {
	Function
}

type TimeIntervalField struct {
	FieldFunction
}

func (f *TimeIntervalField) Format(m *view.Model) {}

func (f *TimeIntervalField) Trans(m *view.Model) view.Node {
	var interval int
	if m.Time.Interval > 0 {
		if m.Time.DatasourceInterval > m.Time.Interval {
			interval = m.Time.DatasourceInterval
		} else {
			interval = m.Time.Interval
		}
	} else {
		interval = int(m.Time.TimeEnd - m.Time.TimeStart)
	}
	return &view.Field{Value: strconv.Itoa(interval)}
}

func (f *TimeIntervalField) SetAlias(alias string) {}

type Time struct {
	Args       []string
	Alias      string
	Withs      []view.Node
	TimeField  string
	Interval   int
	WindowSize int
	Fill       string
}

func (t *Time) Trans(m *view.Model) error {
	t.TimeField = strings.ReplaceAll(t.Args[0], "`", "")
	interval, err := strconv.Atoi(t.Args[1])
	t.Interval = interval
	if err != nil {
		return err
	}
	if len(t.Args) > 2 {
		t.WindowSize, err = strconv.Atoi(t.Args[2])
		if err != nil {
			return err
		}
	} else {
		t.WindowSize = 1
	}
	if len(t.Args) > 3 {
		t.Fill = t.Args[3]
	}
	m.Time.Interval = t.Interval
	if m.Time.Interval > 0 && m.Time.Interval < m.Time.DatasourceInterval {
		m.Time.Interval = m.Time.DatasourceInterval
	}
	m.Time.WindowSize = t.WindowSize
	m.Time.Fill = t.Fill
	m.Time.Alias = t.Alias
	return nil
}

func (t *Time) Format(m *view.Model) {
	toIntervalFunction := "toIntervalSecond"
	var windows string
	w := make([]string, t.WindowSize)
	for i := range w {
		w[i] = strconv.Itoa(i)
	}
	windows = strings.Join(w, ",")
	var innerTimeField string
	if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED {
		innerTimeField = "_" + t.TimeField
		withValue := fmt.Sprintf(
			"toStartOfInterval(%s, toIntervalSecond(%d))",
			t.TimeField, m.Time.DatasourceInterval,
		)
		withAlias := "_" + t.TimeField
		withs := []view.Node{&view.With{Value: withValue, Alias: withAlias}}
		m.AddTag(&view.Tag{Value: withAlias, Withs: withs, Flag: view.NODE_FLAG_METRICS_INNER})
		m.AddGroup(&view.Group{Value: withAlias, Flag: view.GROUP_FLAG_METRICS_INNTER})
	} else if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_UNLAY {
		innerTimeField = t.TimeField
	}
	withValue := fmt.Sprintf(
		"toStartOfInterval(%s, %s(%d)) + %s(arrayJoin([%s]) * %d)",
		innerTimeField, toIntervalFunction, m.Time.Interval, toIntervalFunction, windows, m.Time.Interval,
	)
	withAlias := "_" + t.Alias
	withs := []view.Node{&view.With{Value: withValue, Alias: withAlias}}
	tagField := fmt.Sprintf("toUnixTimestamp(%s)", withAlias)
	m.AddTag(&view.Tag{Value: tagField, Alias: t.Alias, Flag: view.NODE_FLAG_METRICS_OUTER, Withs: withs})
	m.AddGroup(&view.Group{Value: t.Alias, Flag: view.GROUP_FLAG_METRICS_OUTER})
	if m.Time.Fill != "" && m.Time.Interval > 0 {
		m.AddCallback(TimeFill([]interface{}{m}))
	}
}

type TagFunction struct {
	Name  string
	Args  []string
	Alias string
	Withs []view.Node
	Value string
	DB    string
	Table string
}

func (f *TagFunction) SetAlias(alias string) {
	f.Alias = alias
}

func (f *TagFunction) getViewNode() view.Node {
	if f.Value == "" {
		return &view.Tag{Value: f.Alias, Withs: f.Withs}
	} else {
		return &view.Tag{Value: f.Value, Alias: f.Alias}
	}
}

func (f *TagFunction) Check() error {
	switch f.Name {
	case TAG_FUNCTION_MASK:
		_, ok := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		if !ok {
			return errors.New(fmt.Sprintf("function mask not support %s", f.Args[0]))
		}
		maskInt, err := strconv.Atoi(f.Args[1])
		if err != nil {
			return err
		}
		if maskInt < 32 {
			ip4Mask := net.CIDRMask(maskInt, 32)
			_, err = strconv.ParseUint(ip4Mask.String(), 16, 64)
			if err != nil {
				return err
			}
		}
	case TAG_FUNCTION_NODE_TYPE:
		_, ok := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		if !ok {
			return errors.New(fmt.Sprintf("function %s not support %s", f.Name, f.Args[0]))
		}
	case TAG_FUNCTION_ICON_ID:
		_, ok := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		if !ok {
			return errors.New(fmt.Sprintf("function %s not support %s", f.Name, f.Args[0]))
		}
	}
	return nil
}

func (f *TagFunction) Trans(m *view.Model) view.Node {
	fields := f.Args
	switch f.Name {
	case TAG_FUNCTION_TOPK:
		f.Name = fmt.Sprintf("topK(%s)", f.Args[len(f.Args)-1])
		fields = fields[:len(f.Args)-1]
	case TAG_FUNCTION_MASK:
		tagDes, _ := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		if f.Alias == "" {
			f.Alias = "mask"
		}
		maskInt, _ := strconv.Atoi(f.Args[1])
		var ip4MaskInt uint64
		if maskInt >= 32 {
			ip4MaskInt = 4294967295
		} else {
			ip4Mask := net.CIDRMask(maskInt, 32)
			ip4MaskInt, _ = strconv.ParseUint(ip4Mask.String(), 16, 64)
		}
		ip6Mask := net.CIDRMask(maskInt, 128)
		value := fmt.Sprintf(tagDes.TagTranslator, ip4MaskInt, ip6Mask.String())
		f.Withs = []view.Node{&view.With{Value: value, Alias: f.Alias}}
		return f.getViewNode()
	case TAG_FUNCTION_NODE_TYPE:
		tagDes, _ := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		f.Value = tagDes.TagTranslator
		return f.getViewNode()
	case TAG_FUNCTION_ICON_ID:
		tagDes, _ := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
		f.Withs = []view.Node{&view.With{Value: tagDes.TagTranslator, Alias: f.Alias}}
		return f.getViewNode()
	case TAG_FUNCTION_TO_STRING:
		if common.IsValueInSliceString(f.Args[0], []string{"start_time", "end_time"}) {
			tagDes, _ := tag.GetTag(f.Args[0], f.DB, f.Table, f.Name)
			f.Value = tagDes.TagTranslator
			return f.getViewNode()
		}
	case TAG_FUNCTION_NEW_TAG:
		f.Value = f.Args[0]
		if f.Alias == "" {
			f.Alias = fmt.Sprintf("new_tag_%s", f.Args[0])
		}
		return f.getViewNode()
	}
	values := make([]string, len(fields))
	for i, field := range fields {
		var tagField string
		tagDes, ok := tag.GetTag(field, f.DB, f.Table, f.Name)
		if !ok {
			// tag未定义function则走default
			tagDes, ok = tag.GetTag(field, f.DB, f.Table, "default")
			if ok {
				tagField = tagDes.TagTranslator
			}
		} else {
			tagField = tagDes.TagTranslator
		}
		if tagField == "" {
			tagField = field
		}
		values[i] = tagField
	}
	var withValue string
	if len(fields) > 1 {
		if f.Name == "if" {
			withValue = fmt.Sprintf("%s(%s)", f.Name, strings.Join(values, ","))
		} else {
			withValue = fmt.Sprintf("%s([%s])", f.Name, strings.Join(values, ","))
		}
	} else {
		withValue = fmt.Sprintf("%s(%s)", f.Name, values[0])
	}
	if f.Alias == "" {
		f.Value = withValue
	} else {
		f.Withs = []view.Node{&view.With{Value: withValue, Alias: f.Alias}}
	}
	return f.getViewNode()
}

func (f *TagFunction) Format(m *view.Model) {
	node := f.Trans(m)
	m.AddTag(node)
	// metric分层的情况下 function需加入metric外层group
	if m.MetricsLevelFlag == view.MODEL_METRICS_LEVEL_FLAG_LAYERED {
		m.AddGroup(&view.Group{Value: f.Alias, Flag: view.GROUP_FLAG_METRICS_OUTER})
	}
	if f.Name == "icon_id" {
		for resourceStr := range tag.DEVICE_MAP {
			// 以下分别针对单端/双端-0端/双端-1端生成name和ID的Tag定义
			for _, suffix := range []string{"", "_0", "_1"} {
				resourceNameSuffix := resourceStr + suffix
				if f.Args[0] == resourceNameSuffix {
					m.AddGroup(&view.Group{Value: f.Alias})
				}
			}
		}
	}
}