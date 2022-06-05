
//############################
//######   Ajax    ########
//############################

//This ajax can post stuff with ajax over to the pyhton backend
function postAjax(inputUrl, inputData){
      $.ajax({
        url: 'http://127.0.0.1/' + inputUrl,
        data: inputData,
        type: 'POST',
        success: function(response){
          console.log(response);
        },
        error: function(error){
          console.log(error);
        }
      });
}

//This ajax can get data from the database
function getAjax(inputUrl, inputData){
  $.ajax({
    type:"GET",
    dataType: "json",
    data:{'name':'data'},
    url: "http://127.0.0.1/" + inputUrl,
    success: function(data){
        buf1=data;
        console.log(data);
    },
    error: function(error){
      console.log(error);
    }
})
}


//############################
//###### Line charts ########
//############################

document.getElementById("tempChart").style.display = "none";
document.getElementById("humidChart").style.display = "none";

function toggledisplay(elementID) {
  (function (style) {
    style.display = style.display === "none" ? "" : "none";
  })(document.getElementById(elementID).style);
}

const labels = ["10.", "11.", "12.", "13.", "14.", "15.", "16.", "17."];

const dataTemp = {
  labels: labels,
  datasets: [
    {
      label: "Container 1",
      backgroundColor: "rgb(255, 99, 132)",
      borderColor: "rgb(255, 99, 132)",
      data: [25, 20, 21, 30, 35, 32, 36, 26]
    },
    {
      label: "Container 2",
      backgroundColor: "rgb(10, 99, 132)",
      borderColor: "rgb(100, 99, 132)",
      data: [26, 22, 20, 28, 33, 36, 34, 28]
    },
    {
      label: "Container 3",
      backgroundColor: "rgb(255, 99, 10)",
      borderColor: "rgb(100, 99, 132)",
      data: [27, 23, 22, 27, 30, 34, 33, 30]
    }
  ]
};
const dataHumid = {
  labels: labels,
  datasets: [
    {
      label: "Container 1",
      backgroundColor: "rgb(255, 99, 132)",
      borderColor: "rgb(255, 99, 132)",
      data: [14, 10, 20, 18, 15, 25, 10, 26]
    },
    {
      label: "Container 2",
      backgroundColor: "rgb(10, 99, 132)",
      borderColor: "rgb(100, 99, 132)",
      data: [17, 19, 5, 17, 20, 30, 20, 17]
    },
    {
      label: "Container 3",
      backgroundColor: "rgb(255, 99, 10)",
      borderColor: "rgb(100, 99, 132)",
      data: [10, 12, 9, 22, 12, 14, 18, 15]
    }
  ]
};

const configTemp = {
  type: "line",
  data: dataTemp,
  options: {}
};

const configHumid = {
  type: "line",
  data: dataHumid,
  options: {}
};
const mytempChart = new Chart(document.getElementById("tempChart"), configTemp);
const myHumidChart = new Chart(document.getElementById("humidChart"),configHumid);

//############################
//######## Pie charts ########
//############################
function sliceSize(dataNum, dataTotal) {
  return (dataNum / dataTotal) * 360;
}

function addSlice(id, sliceSize, pieElement, offset, sliceID, color) {
  $(pieElement).append(
    "<div class='slice " + sliceID + "'><span></span></div>"
  );
  var offset = offset - 1;
  var sizeRotation = -179 + sliceSize;

  $(id + " ." + sliceID).css({
    transform: "rotate(" + offset + "deg) translate3d(0,0,0)"
  });

  $(id + " ." + sliceID + " span").css({
    transform: "rotate(" + sizeRotation + "deg) translate3d(0,0,0)",
    "background-color": color
  });
}

function iterateSlices(
  id,
  sliceSize,
  pieElement,
  offset,
  dataCount,
  sliceCount,
  color
) {
  var maxSize = 179,
    sliceID = "s" + dataCount + "-" + sliceCount;

  if (sliceSize <= maxSize) {
    addSlice(id, sliceSize, pieElement, offset, sliceID, color);
  } else {
    addSlice(id, maxSize, pieElement, offset, sliceID, color);
    iterateSlices(
      id,
      sliceSize - maxSize,
      pieElement,
      offset + maxSize,
      dataCount,
      sliceCount + 1,
      color
    );
  }
}

function createPie(id) {
  var listData = [],
    listTotal = 0,
    offset = 0,
    i = 0,
    pieElement = id + " .pie-chart__pie";
  dataElement = id + " .pie-chart__legend";

  color = [
    "cornflowerblue",
    "olivedrab",
    "orange",
    "tomato",
    "crimson",
    "purple",
    "turquoise",
    "forestgreen",
    "navy"
  ];

  color = shuffle(color);

  $(dataElement + " span").each(function () {
    listData.push(Number($(this).html()));
  });

  for (i = 0; i < listData.length; i++) {
    listTotal += listData[i];
  }

  for (i = 0; i < listData.length; i++) {
    var size = sliceSize(listData[i], listTotal);
    iterateSlices(id, size, pieElement, offset, i, 0, color[i]);
    $(dataElement + " li:nth-child(" + (i + 1) + ")").css(
      "border-color",
      color[i]
    );
    offset += size;
  }
}

function shuffle(a) {
  var j, x, i;
  for (i = a.length; i; i--) {
    j = Math.floor(Math.random() * i);
    x = a[i - 1];
    a[i - 1] = a[j];
    a[j] = x;
  }

  return a;
}

function createPieCharts() {
  createPie(".pieID--container1");
  createPie(".pieID--container2");
  createPie(".pieID--container3");
}

createPieCharts();
